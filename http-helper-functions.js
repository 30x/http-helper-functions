'use strict'
const http = require('http')
const https = require('https')
const jsonpatch= require('./jsonpatch')
const randomBytes = require('crypto').randomBytes
const createVerify = require('crypto').createVerify
const createHmac = require('crypto').createHmac
const url = require('url')
const util = require('util')
const httpKeepAliveAgent = new http.Agent({ keepAlive: true })
const httpsKeepAliveAgent = new https.Agent({ keepAlive: true })
const querystring = require('querystring')
const fs = require('fs')

const INTERNAL_SCHEME = process.env.INTERNAL_SCHEME || 'http'
const INTERNAL_PROTOCOL = INTERNAL_SCHEME + ':'
const INTERNALURLPREFIX = ''
const INTERNAL_SY_ROUTER_PORT = process.env.INTERNAL_SY_ROUTER_PORT
const INTERNAL_SY_ROUTER_HOST = process.env.INTERNAL_SY_ROUTER_HOST
const SHIPYARD_PRIVATE_SECRET = process.env.SHIPYARD_PRIVATE_SECRET !== undefined ? new Buffer(process.env.SHIPYARD_PRIVATE_SECRET).toString('base64') : undefined
const MIN_TOKEN_VALIDITY_PERIOD = process.env.MIN_TOKEN_VALIDITY_PERIOD || 5000
const CHECK_PERMISSIONS = process.env.CHECK_PERMISSIONS == 'false' ? false : true
const CHECK_IDENTITY = CHECK_PERMISSIONS || (process.env.CHECK_IDENTITY == 'true')
const RUNNING_BEHIND_APIGEE_EDGE = process.env.RUNNING_BEHIND_APIGEE_EDGE == 'true'
const TOKEN_KEY_REFERESH_INTERVAL = process.env.TOKEN_KEY_REFERESH_INTERVAL ? parseInt(process.env.TOKEN_KEY_REFERESH_INTERVAL) : 5*60*1000 // 5 min refresh

const BROWSER_ACCESSIBLE_HOST = process.env.BROWSER_ACCESSIBLE_HOST
const XSRF_SECRET = process.env.XSRF_SECRET
const XSRF_TOKEN_TIMEOUT = process.env.XSRF_SECRET || 2*60*60*1000 // 2 hrs

function log(functionName, text) {
  console.log(new Date().toISOString(), process.env.COMPONENT_NAME, functionName, text)
}

function keepAliveAgent(protocol) {
  return protocol == 'https:' ? httpsKeepAliveAgent : httpKeepAliveAgent
}

function getHostIPFromK8SThen(callback) {
  var token = fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token').toString()
  var cert = fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt').toString()
  var ns = fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/namespace').toString()
  var podName = process.env.POD_NAME

  var headers = {
    Authorization: `Bearer ${token}`
  }
  var options = {
    protocol: 'https:',
    hostname: 'kubernetes.default',
    cert: cert,
    rejectUnauthorized: false,
    path: `/api/v1/namespaces/${ns}/pods/${podName}`,
    method: 'GET',
    headers: headers
  }
  var clientReq = https.request(options, function(res) {
    res.setEncoding('utf8')
    var body = ''
    res.on('data', chunk => body += chunk)
    res.on('end', function() {
      if (res.statusCode == 200) {
        var hostIP = JSON.parse(body).status.hostIP
        log('http-helper-functions:getHostIPFromK8SThen', `retrieved Kubernetes hostIP : ${hostIP}from K8S API`)
        callback(null, hostIP)
      } else {
        var err = `unable to resolve Host IP. statusCode: ${res.statusCode} body: ${body}`
        log('http-helper-functions:getHostIPFromK8SThen', err)
        callback(err)
      }
    })
  })
  clientReq.on('error', function (err) {
    log('http-helper-functions:getHostIPFromK8SThen', `error ${err}`)
  })
  clientReq.end()
}

function getHostIPFromFileThen(callback) {
  var data = fs.readFileSync('/proc/net/route')
  var hexHostIP = data.toString().split('\n')[1].split('\t')[2]
  var hostIP = [3,2,1,0].map((i) => parseInt(hexHostIP.slice(i*2,i*2+2), 16)).join('.')
  log('http-helper-functions:getHostIPFromFileThen', `retrieved Kubernetes hostIP: ${hostIP} from /proc/net/route`)
  callback(null, hostIP)
}

function getHostIPThen(callback) {
  getHostIPFromFileThen(callback)
}

function setContentWithLengthAndType(headers, body) {
  if (headers.accept === undefined)
    headers.accept = 'application/json'
  if (body) {
    var contentType = headers['content-type']
    if (contentType == null)
      contentType = headers['content-type'] = 'application/json'
    if (!(typeof body == 'string' || (typeof body == 'object' && (body instanceof Buffer || body instanceof ArrayBuffer)))) // body is not a string, Buffer or ArrayBuffer
      if (contentType.startsWith('application') && contentType.endsWith('json'))
        body = JSON.stringify(body)
    headers['content-length'] = Buffer.byteLength(body)
  } else
    // if we are not going to send a body, it is important that we also don't have a content-length header otherwise http will hang.
    // make sure there isn't a stray one hanging around
    delete headers['content-length']
  return body
}

const letters16 = 'abcdefghijklmnopqrst'
function generateIdentifier() {
  var buf = randomBytes(8), rslt = ''
  for (var i = 0; i < 8; i++) {
    rslt += letters16[buf[i] >>> 4]
    rslt += letters16[buf[i] & 0xf]
  }
  return rslt
}

function sendInternalRequest(method, resourceURL, headers, body, callback) {
  if (typeof headers == 'function') {
    callback = headers
    headers = {}
  }
  var parsedURL = resourceURL.startsWith('//') ? url.parse(INTERNAL_PROTOCOL + resourceURL) : url.parse(resourceURL) // amazingly, url.parse parses URLs that begin with // wrongly
  let hostname = parsedURL.host == null ? INTERNAL_SY_ROUTER_HOST : parsedURL.hostname
  let port = parsedURL.host == null ? INTERNAL_SY_ROUTER_PORT : parsedURL.port
  let protocol = parsedURL.protocol == null ? INTERNAL_PROTOCOL : parsedURL.protocol
  let pathRelativeURL = parsedURL.path
  var id = generateIdentifier()
  log('http-helper-functions:sendInternalRequest', `id: ${id} method: ${method} hostname: ${process.env.INTERNAL_SY_ROUTER_HOST}${INTERNAL_SY_ROUTER_PORT ? `:${INTERNAL_SY_ROUTER_PORT}` : ''} url: ${pathRelativeURL}`)
  body = setContentWithLengthAndType(headers, body)
  if (SHIPYARD_PRIVATE_SECRET !== undefined)
    headers['x-routing-api-key'] = SHIPYARD_PRIVATE_SECRET
  if (parsedURL.host != null && 'host' in headers) {
    headers = Object.assign({}, headers)
    headers.host = parsedURL.host
  }
  var options = {
    protocol: protocol,
    hostname: hostname,
    path: pathRelativeURL,
    method: method,
    headers: headers,
    agent: keepAliveAgent(protocol)
  }
  if (port)
    options.port = port
  var startTime = Date.now()
  var clientReq = (protocol == 'https:' ? https : http).request(options, function(clientRes) {
    log('http-helper-functions:sendInternalRequest', `id: ${id} received response after ${Date.now() - startTime} millisecs. method: ${method} hostname: ${hostname}${port ? `:${port}` : ''} url: ${pathRelativeURL}`)
    callback(null, clientRes)
  })
  clientReq.setTimeout(300000, () => {
    var msgText = `socket timeout after ${Date.now() - startTime} millisecs pathRelativeURL: ${pathRelativeURL}`
    var msg = {msg: 'socket timeout', msgText: msgText}
    log('http-helper-functions:sendInternalRequest', msgText)
    clientReq.abort()
    callback(msg)
  })
  clientReq.on('error', function (err) {
    var the_options = Object.assign({}, options)
    delete the_options.agent
    let targetUrl = `${options.hostname}${options.port ? `:${options.port}` : ''}${options.path}`
    log('http-helper-functions:sendInternalRequest', `id: ${id} error ${err} targetUrl: ${targetUrl} options: options: ${util.inspect(the_options)}`)
    callback(err)
  })
  if (body)
    clientReq.write(body)
  clientReq.end()
}

function sendInternalRequestThen(res, method, resourceURL, headers, body, callback) {
  if (typeof headers == 'function')
    [callback, headers] = [headers, {}]
  else if (headers == null)
    headers = {}
  sendInternalRequest(method, resourceURL, headers, body, function(errStr, clientRes) {
    if (errStr) {
      let parsedURL = resourceURL.startsWith('//') ? url.parse(INTERNAL_PROTOCOL + resourceURL) : url.parse(resourceURL) // amazingly, url.parse parses URLs that begin with // wrongly
      let pathRelativeURL = parsedURL.path
      let err = {
        err: errStr,
        host: headers.host,
        path: pathRelativeURL,
        internalRouterHost: process.env.INTERNAL_SY_ROUTER_HOST,
        internalRouterPort: INTERNAL_SY_ROUTER_PORT
      }
      log('http-helper-functions:sendInternalRequestThen', `error ${err} method ${method} host: ${headers.host} path ${pathRelativeURL} headers ${util.inspect(headers)}`)
      internalError(res, {msg: 'unable to send internal request', err: err, method: method, host: headers.host, path: pathRelativeURL, headers: headers})
    } else
      callback(clientRes)
  })
}

function withInternalResourceDo(res, resourceURL, headers, callback) {
  if (!headers.accept)
    headers.accept = 'application/json'
  sendInternalRequestThen(res, 'GET', resourceURL, headers, null, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, body => {
      if (clientRes.statusCode == 200)
        callback(body, clientRes)
      else
        internalError(res, {msg: 'unable to retrieve internal resource', url: resourceURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

function patchInternalResourceThen(res, resourceURL, headers, patch, callback) {
  if (!headers.accept)
    headers.accept = 'application/json'
  sendInternalRequestThen(res, 'PATCH', resourceURL, headers, patch, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, body => {
      if (clientRes.statusCode == 200)
        callback(body, clientRes)
      else
        internalError(res, {msg: 'unable to patch internal resource', url: resourceURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

function deleteInternalResourceThen(res, resourceURL, headers, callback) {
  if (!headers.accept)
    headers.accept = 'application/json'
  sendInternalRequestThen(res, 'DELETE', resourceURL, headers, null, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, responseBody => {
      if (Math.floor(clientRes.statusCode / 100) == 2)
        callback(responseBody, clientRes)
      else
        internalError(res, {msg: 'unable to post to internal resource', url: resourceURL, statusCode: clientRes.statusCode, responseBody: responseBody})
    })
  })
}

function postToInternalResourceThen(res, resourceURL, headers, requestBody, callback) {
  if (!headers.accept)
    headers.accept = 'application/json'
  sendInternalRequestThen(res, 'POST', resourceURL, headers, requestBody, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, responseBody => {
      if (Math.floor(clientRes.statusCode / 100) == 2)
        callback(responseBody, clientRes)
      else
        respond({headers: {}}, res, clientRes.statusCode, {}, responseBody)
    })
  })
}

function flowThroughHeaders(req) {
  var headers = {}
  var reqHeaders = req.headers
  var auth = reqHeaders.authorization
  if (auth)
    headers.authorization = auth
  var host = reqHeaders.host
  if (host)
    headers.host = host
  var requestID = req.headers['x-request-id']
  if (requestID)
    headers['x-request-id'] = requestID
  return headers
}

function sendExternalRequest(method, targetUrl, headers, body, callback) {
  if (typeof headers == 'function') {
    callback = headers
    headers = {}
  }
  var id = generateIdentifier()
  log('http-helper-functions:sendExternalRequest', `id: ${id} method: ${method} url: ${targetUrl}`)
  body = setContentWithLengthAndType(headers, body)
  var urlParts = url.parse(targetUrl)
  var options = {
    protocol: urlParts.protocol,
    hostname: urlParts.hostname,
    path: urlParts.path,
    method: method,
    headers: headers,
    agent: keepAliveAgent(urlParts.protocol)
  }
  if (urlParts.port)
    options.port = urlParts.port
  var clientReq = (urlParts.protocol == 'https:' ? https : http).request(options, function(clientRes) {
    log('http-helper-functions:sendExternalRequest', `id: ${id} received response after ${Date.now() - startTime} millisecs. method: ${method} url: ${targetUrl}`)
    callback(null, clientRes)
  })
  var startTime = Date.now()
  clientReq.setTimeout(300000, () => {
    var msg = `socket timeout after ${Date.now() - startTime} millisecs targetUrl: ${targetUrl}`
    log('http-helper-functions:sendExternalRequest', `id: ${id} socket timeout after ${Date.now() - startTime} millisecs targetUrl: ${targetUrl}`)
    clientReq.abort()
    callback(msg)
  })
  clientReq.on('error', function (err) {
    log('http-helper-functions:sendExternalRequest', `id: ${id} error ${util.inspect(err)} targetUrl: ${targetUrl} options: options: ${util.inspect(options)}`)
    callback(err)
  })
  if (body)
    clientReq.write(body)
  clientReq.end()
}

function sendExternalRequestThen(res, method, targetUrl, headers, body, callback) {
  if (typeof headers == 'function')
    [callback, headers] = [headers, {}]
  else if (headers == null)
    headers = {}
  sendExternalRequest(method, targetUrl, headers, body, function(err, clientRes) {
    if (err) {
      err.headers = headers
      err.targetUrl = targetUrl
      err.method = method
      log('http-helper-functions:sendExternalRequestThen', `error ${err}`)
      internalError(res, {msg: `unable to send external request. method: ${method} url: ${targetUrl}`, headers: headers, err: err})
    } else
      callback(clientRes)
  })
}

function withExternalResourceDo(res, resourceURL, headers, callback) {
  sendExternalRequestThen(res, 'GET', resourceURL, headers, null, function(clientRes) {
    getClientResponseObject(res, clientRes, null, body => {
      if (clientRes.statusCode == 200)
        callback(body, clientRes)
      else
        internalError(res, {msg: 'unable to retrieve internal resource', url: resourceURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

function patchExternalResourceThen(res, resourceURL, headers, patch, callback) {
  sendInternalRequestThen(res, 'PATCH', resourceURL, headers, patch, function(clientRes) {
    getClientResponseObject(res, clientRes, null, body => {
      if (clientRes.statusCode == 200)
        callback(body, clientRes)
      else
        internalError(res, {msg: 'unable to patch internal resource', url: resourceURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

function postToExternalResourceThen(res, resourceURL, headers, requestBody, callback) {
  sendInternalRequestThen(res, 'POST', resourceURL, headers, requestBody, function(clientRes) {
    getClientResponseObject(res, clientRes, null, responseBody => {
      if (Math.floor(clientRes.statusCode / 100) == 2)
        callback(responseBody, clientRes)
      else
        internalError(res, {msg: 'unable to post to internal resource', url: resourceURL, statusCode: clientRes.statusCode, responseBody: responseBody})
    })
  })
}

function getServerPostObject(req, res, callback) {
  var body = ''
  req.on('data', function (data) {
    if (body.length + data.length > 1e6)
      return req.connection.destroy()
    body += data
  })
  req.on('end', function () {
    var contentType = req.headers['content-type']
    if (contentType === undefined || (contentType.startsWith('application/', 0) > -1 && contentType.endsWith('json'))) {
      var jso
      try {
        jso = JSON.parse(body)
      }
      catch (err) {
        log('http-helper-functions:getServerPostObject', `invalid JSON: ${err.message} body: ${body}`)
        badRequest(res, `invalid JSON: ${err.message} body: ${body}` )
      }
      if (jso)
        callback(internalizeURLs(jso, req.headers.host, contentType))
    } else
      badRequest(res, 'input must be JSON')
  })
}

function getServerPostBuffer(req, callback) {
  var body = []
  req.on('data', function (data) {
    if (body.reduce((total, item) => total + item.length, 0) + data.length > 1e6)
      return req.connection.destroy()
    body.push(data)
  })
  req.on('end', () => callback(Buffer.concat(body)))
}

function getClientResponseBody(res, callback) {
  res.setEncoding('utf8')
  var body = ''
  res.on('data', chunk => body += chunk)
  res.on('end', () => callback(body))
}

function getClientResponseObject(errorHandler, res, host, callback) {
  getClientResponseBody(res, function(body) {
    var contentType = res.headers['content-type']
    if (contentType === undefined || (contentType.startsWith('application/', 0) > -1 && contentType.endsWith('json')))
      if (body == '')
        callback()
      else {
        var jso
        try {
          jso = JSON.parse(body)
        }
        catch (err) {
          log('http-helper-functions:getClientResponseObject', body)
          internalError(errorHandler, {msg: 'invalid JSON in response', err: err, body: body} )
        }
        if (jso)
          callback(internalizeURLs(jso, host, contentType))
      } else
        internalError(errorHandler, {msg: 'response not JSON', contentType: contentType, body: body})
  })
}

function getClientResponseBuffer(res, callback) {
  var body = []
  res.on('data', chunk => body.push(chunk))
  res.on('end', () => callback(Buffer.concat(body)))
}

function getClaimsFromToken(token) {
  if (typeof token == 'string') {
    var claims64 = token.split('.')
    if (claims64.length != 3) {
      return null
    } else {
      var claimsString = new Buffer(claims64[1], 'base64').toString()
      var claims = JSON.parse(claimsString)
      return claims
    }
  } else
    return null
}

function getUserFromToken(token) {
  var claims = getClaimsFromToken(token)
  return claims == null ? null : `${claims.iss}#${claims.sub}`
}

function getToken(auth) {
  if (typeof auth == 'string'){
    var auth_parts = auth.match(/\S+/g)
    if (auth_parts.length < 2 || auth_parts[0].toLowerCase() != 'bearer')
      return null
    else
      return auth_parts[1]
  } else
    return null
}

function getUser(auth) {
  return getUserFromToken(getToken(auth))
}

function getTokenFromReq(req) {
  let token = req.__xxx_token__
  if (token === undefined) {  
    token = req.__xxx_token__ = getToken(req.authorization);
  }
  return token
}

function getClaimsFromReq(req) {
  let claims = req.__xxx_claims__;
  if (claims == undefined) {
    let token = getTokenFromReq(req);
    claims = req.__xxx_claims__ = getClaimsFromToken(token)
  }
  return claims    
}

function getUserFromReq(req) {
  let user = req.__xxx_user__
  if (user === undefined) {
    let claims = getClaimsFromReq(req)
    user = req.__xxx_user__ = claims == null ? null : `${claims.iss}#${claims.sub}`
    }
  return user
}

function getScopes(auth) {
  let claims = getClaimsFromToken(getToken(auth));
  return claims !== null && claims !== undefined && claims.scope ? claims.scope : []
}

function methodNotAllowed(req, res, allow) {
  var body = 'Method not allowed. request-target: ' + req.url + ' method: ' + req.method + '\n'
  body = JSON.stringify(body)
  res.writeHead(405, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body),
                      'Allow': allow.join(', ') })
  res.end(body)
}

function notFound(req, res, body) {
  body = body || `Not Found. component: ${process.env.COMPONENT_NAME} request-target: //${req.headers.host}${req.url} method: ${req.method}\n`
  body = JSON.stringify(body)
  res.writeHead(404, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function forbidden(req, res, body) {
  body = body || `Forbidden. component: ${process.env.COMPONENT_NAME} request-target: //${req.headers.host}${req.url} method: ${req.method} user: ${getUser(req.headers.authorization)}\n`
  body = JSON.stringify(body)
  res.writeHead(403, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function unauthorized(req, res, body) {
  body = body || 'Unauthorized. request-target: ' + req.url
  body = typeof body == 'object' ? JSON.stringify(body) : body
  res.writeHead(401, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function badRequest(res, err) {
  var body = JSON.stringify(err)
  res.writeHead(400, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function internalError(res, err) {
  var body = JSON.stringify(err)
  res.writeHead(500, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function duplicate(res, err) {
  var body = JSON.stringify(err)
  res.writeHead(409, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function found(req, res, body, etag, contentLocation, contentType) {
  var headers = {}
  if (contentLocation !== undefined)
    headers['Content-Location'] = externalizeURLs(contentLocation, req.headers.host)
  else
    headers['Content-Location'] = req.url //todo - handle case where req.url includes http://authority
  if (etag !== undefined)
    headers['Etag'] = etag
  respond(req, res, 200, headers, body, contentType)
}

function created(req, res, body, location, etag, contentType) {
  var headers =  {}
  if (location !== undefined)
    headers['Location'] = externalizeURLs(location, req.headers.host)
  if (etag !== undefined)
    headers['Etag'] = etag
  respond(req, res, 201, headers, body, contentType)
}

function respond(req, res, status, headers, body, contentType) {
  if (body !== undefined) {
    // If contentType is provided, body is assumed to be the representation of the resource, ready to be sent in the response. If
    // contentType is not provided, the body is assumed to be the state of the resource in Javascript objects. As such, it is
    // subject to content negotiation of the response format.
    // ToDo: make the code match this comment or change the comment
    var wantsHTML = req.headers.accept !== undefined && req.headers.accept.startsWith('text/html')
    if (!('content-type' in headers))
      headers['content-type'] = contentType ? contentType : wantsHTML ? 'text/html' : 'application/json'
    externalizeURLs(body, req.headers.host)
    var contentType = headers['content-type']
    var isJson = contentType.startsWith('application/') && contentType.endsWith('json')
    body = body instanceof Buffer ? body : contentType == 'text/html' ? toHTML(body) : contentType == 'text/plain' ? body.toString() : isJson ? JSON.stringify(body) : body.toString()
    headers['Content-Length'] = Buffer.byteLength(body)
    res.writeHead(status, headers)
    res.end(body)
  } else {
    res.writeHead(status, headers)
    res.end()
  }
}

const subdelims = [33, 36, 38, 39, 40, 41, // "!" / "$" / "&" / "'" / "(" / ")"
                   42, 43, 44, 59, 61 ]  // / "*" / "+" / "," / ";" / "="
function isValidPathCharacter (code) {
  if (code >= 48 && code <= 57) // decimal
    return true
  if (code >= 65 && code <= 90) // uppercase letter
    return true
  if (code >= 97 && code <= 122) // lowercase letter
    return true
  if (code == 45 || code == 46 || code == 95 || code == 126) // -._~
    return true
  if (subdelims.indexOf(code) > -1)
    return true
  if (code == 58 || code == 64) // :@
    return true
  return false
}

const urlChars = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
function pathCharacter (code) {
  return urlChars.charAt(code - 32)
}

function getEncodingLength(code) {
  if (code == 226) // %E2
    return 9
  else if (code == 198 || code == 197 || code == 203 || code == 194 || code == 195) // %C6, %C5, %CB, %C2, %C3
    return 6
  else
    return 3
}

function normalizeURLPart(path) {
  // This method takes out any extraneous percent encoding, leaving only the ones that are necessary
  if (path) {
    var rslt
    for (let i=0; i<path.length; i++) {
      let char = path.charAt(i)
      if (char == '%') {
        let code = parseInt(path.slice(i+1, i+3), 16)
        if (isValidPathCharacter(code)) { // it should not be encoded — decode it
          if (!rslt)
            rslt = path.slice(0, i)
          rslt += pathCharacter(code)
          i += getEncodingLength(path, code, i) - 1
        } else {
          let encodingLength = getEncodingLength(path, code, i)
          if (rslt)
            rslt += path.slice(i, i + encodingLength)
          i += encodingLength - 1
        }
      } else
        if (rslt)
          rslt += char
    }
    return rslt || path
  } else
    return path
}

function normalizeURL(theURIReference) {
  let parsedURL = url.parse(theURIReference)
  if (parsedURL.query && RUNNING_BEHIND_APIGEE_EDGE) {
    let sq = decodeURIComponent(parsedURL.query)
    parsedURL.search = '?' + sq
    return parsedURL.format()
  } else
    return theURIReference
}

function internalizeURL(anURL, authority) {
  var decodedURL = normalizeURL(anURL)
  var httpString = 'http://' + authority
  var httpsString = 'https://' + authority
  var schemelessString = '//' + authority
  if (decodedURL.startsWith(httpString))
    return INTERNALURLPREFIX + decodedURL.substring(httpString.length)
  else if (decodedURL.startsWith(httpsString))
    return INTERNALURLPREFIX + decodedURL.substring(httpsString.length)
  else if (decodedURL.startsWith(schemelessString))
    return INTERNALURLPREFIX + decodedURL.substring(schemelessString.length)
  else if (decodedURL.startsWith('/') || decodedURL.startsWith('http'))
    return INTERNALURLPREFIX + decodedURL
  else
    return decodedURL
}

var re = /^[^\s"'<>]+$/
function looksLikeAnURL(jsObject) {
  return typeof jsObject == 'string' && (jsObject.startsWith('http') || jsObject.startsWith('/') || jsObject.startsWith('%2F')) && jsObject.match(re)
}

function internalizeURLs(jsObject, authority, contentType) {
  //strip the http://authority or https://authority from the front of any urls
  if (authority)
    if (Array.isArray(jsObject))
      for (var i = 0; i < jsObject.length; i++)
        jsObject[i] = internalizeURLs(jsObject[i], authority, contentType)
    else if (typeof jsObject == 'object')
      if (contentType == 'application/json-patch+json') {
        if (jsObject['value'] !== undefined)
          jsObject['value'] = internalizeURLs(jsObject['value'], authority)
      } else
        for (var key in jsObject) {
          if (jsObject.hasOwnProperty(key))
            jsObject[key] = internalizeURLs(jsObject[key], authority)
        }
    else if (looksLikeAnURL(jsObject))
      return internalizeURL(jsObject, authority)
  return jsObject
}

function externalizeURLs(jsObject, authority) {
  //add http://authority or https://authority to the front of any urls
  if (Array.isArray(jsObject))
    for (var i = 0; i < jsObject.length; i++)
      jsObject[i] = externalizeURLs(jsObject[i], authority)
  else if (typeof jsObject == 'object')
    for(var key in jsObject) {
      if (jsObject.hasOwnProperty(key))
        jsObject[key] = externalizeURLs(jsObject[key], authority)
    }
  else if (typeof jsObject == 'string')
    if (jsObject.startsWith(INTERNALURLPREFIX)) {
      var prefix = '' // `//${authority}`
      return prefix + jsObject.substring(INTERNALURLPREFIX.length)
    }
  return jsObject
}

function mergePatch(target, patch) {
  if (typeof patch == 'object' && !Array.isArray(patch)) {
    if (typeof target != 'object')
      target = {} // don't just return patch since it may have nulls — perform the merge
    else
      target = Object.assign({}, target)
    for (var name in patch) {
      var value = patch[name]
      if (value === null)
        if (name in target)
          delete target[name]
        else {}
      else
        target[name] = mergePatch(target[name], value)
    }
    return target
  } else
    return patch
}

function applyPatch(reqHeaders, res, target, patch, callback) {
  if ('content-type' in reqHeaders)
    if (reqHeaders['content-type'] == 'application/merge-patch+json')
      callback(mergePatch(target, patch), reqHeaders['content-type'])
    else if (reqHeaders['content-type'] == 'application/json-patch+json') {
      try {
        var patchedDoc = jsonpatch.apply_patch(target, patch)
      }
      catch(err) {
        return badRequest(res, `err: ${err} patch: ${util.inspect(patch)}`)
      }
      callback(patchedDoc, reqHeaders['content-type'])
    }
    else
      badRequest(res, `unknown PATCH content-type: ${reqHeaders['content-type']}`)
  else
    badRequest(res, 'PATCH headers missing content-type for patch')
}

function setStandardCreationProperties(req, resource, user) {
  if (resource.creator)
    return 'may not set creator'
  else
    resource.creator = user
  if (resource.modifier)
    return 'may not set modifier'
  if (resource.created)
    return 'may not set created'
  else
    resource.created = new Date().toISOString()
  if (resource.modified)
    return 'may not set modified'
  return null
}

function toHTML(body) {
  const increment = 25
  function valueToHTML(value, indent, name) {
    if (typeof value == 'string')
      if (value.startsWith('http') || value.startsWith('./') || value.startsWith('/'))
        return `<a href="${value}"${name === undefined ? '': ` property="${name}"`}>${value}</a>`
      else
        return `<span${name === undefined ? '': ` property="${name}"`} datatype="string">${value}</span>`
    else if (typeof value == 'number')
      return `<span${name === undefined ? '': ` property="${name}"`} datatype="number">${value.toString()}</span>`
    else if (typeof value == 'boolean')
      return `<span${name === undefined ? '': ` property="${name}"`} datatype="boolean">${value.toString()}</span>`
    else if (Array.isArray(value)) {
      var rslt = value.map(x => `<li>${valueToHTML(x, indent)}</li>`)
      return `<ol${name === undefined ? '': ` property="${name}"`}>${rslt.join('')}</ol>`
    } else if (typeof value == 'object') {
      var rslt = Object.keys(value).map(name => propToHTML(name, value[name], indent+increment))
      return `<div${value.self === undefined ? '' : ` resource=${value.self}`} style="padding-left:${indent+increment}px">${rslt.join('')}</div>`
    }
  }
  function propToHTML(name, value, indent) {
    return `<p>${name}: ${valueToHTML(value, indent, name)}</p>`
  }
  return `<!DOCTYPE html><html><head></head><body>${valueToHTML(body, -increment)}</body></html>`
}

// The following function adapted from https://github.com/broofa/node-uuid4 under MIT License
// Copyright (c) 2010-2012 Robert Kieffer
var toHex = Array(256)
for (var val = 0; val < 256; val++)
  toHex[val] = (val + 0x100).toString(16).substr(1)
function uuid4() {
  var buf = randomBytes(16)
  buf[6] = (buf[6] & 0x0f) | 0x40
  buf[8] = (buf[8] & 0x3f) | 0x80
  var i=0
  return  toHex[buf[i++]] + toHex[buf[i++]] +
          toHex[buf[i++]] + toHex[buf[i++]] + '-' +
          toHex[buf[i++]] + toHex[buf[i++]] + '-' +
          toHex[buf[i++]] + toHex[buf[i++]] + '-' +
          toHex[buf[i++]] + toHex[buf[i++]] + '-' +
          toHex[buf[i++]] + toHex[buf[i++]] +
          toHex[buf[i++]] + toHex[buf[i++]] +
          toHex[buf[i++]] + toHex[buf[i++]]
}
// End of section of code adapted from https://github.com/broofa/node-uuid4 under MIT License

function errorHandler(func) {
  var statusCode
  var headers
  return {
    writeHead: function(statusArg, headersArg) {
      statusCode = statusArg
      headers = headersArg
    },
    end: function(body) {
      func({statusCode: statusCode, headers:headers, body:body})
    }
  }
}

// Given a clientId and secret and the URL of an issuer's oauth token resource, return a valid token from the issuer
function withValidClientToken(errorHandler, token, clientID, clientSecret, tokenURL, callback) {
  if (CHECK_PERMISSIONS || CHECK_IDENTITY) {
    var claims = getClaimsFromToken(token)
    if (claims != null && (claims.exp * 1000) > Date.now() + MIN_TOKEN_VALIDITY_PERIOD)
      callback()
    else {
      var headers = {'content-type': 'application/x-www-form-urlencoded;charset=utf-8', accept: 'application/json;charset=utf-8'}
      var body = `grant_type=client_credentials&client_id=${encodeURIComponent(clientID)}&client_secret=${encodeURIComponent(clientSecret)}`
      sendExternalRequestThen(errorHandler, 'POST', tokenURL, headers, body, function(clientRes) {
        getClientResponseBody(clientRes, function(resp_body) {
          if (clientRes.statusCode == 200) {
            token = JSON.parse(resp_body).access_token
            log('withValidClientToken', `retrieved token for: ${clientID}`)
            callback(token)
          } else {
            log('withValidClientToken', `unable to retrieve token. tokenURL: ${tokenURL}, headers: ${util.inspect(headers)}`)
            badRequest(errorHandler, {msg: 'unable to retrieve client token', body: resp_body})
          }
        })
      })
    }
  } else
    callback()
}

function isValidToken(token, publicKeys, scopes, callback) {
  if (publicKeys.length == 0)
    return callback(false, {msg: 'no keys provided'})
  if (typeof token != 'string')
    return callback(false, {msg: 'no token provided'})
  let tokenParts = token.split('.')
  if (tokenParts.length != 3)
    return callback(false, {msg: 'malformed token'})
  let header = JSON.parse(Buffer.from(tokenParts[0], 'base64').toString())
  if (header.alg != 'RS256')
    return callback(false, {msg: 'token alg must be RS256', found: header.alg})
  let claims = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString())
  let signature = tokenParts[2]
  let signedPart = token.substring(0, token.length - signature.length - 1)
  for (let i = 0; i< publicKeys.length; i++) {
    let verified = createVerify('RSA-SHA256').update(signedPart).verify(publicKeys[i], signature, 'base64')
    if (verified)
      if (claims.nbf && Date.now() < claims.nbf*1000)
        return callback(false, {msg: 'token not yet valid'})
      else if (claims.exp && Date.now() > claims.exp*1000)
        return callback(false, {msg: 'token expired'})
      else
        if (scopes && scopes.length > 0)
          if (claims && claims.scope && claims.scope.length > 0) {
            let missingScopes = scopes.filter(sc => claims.scope.indexOf(sc) == -1) 
            if (missingScopes.length > 0)
              return callback(false, {msg: 'required scopes missing from token', missingScopes: missingScopes, claims: claims})
            else
              return callback(true)
          } else
            return callback(false, {msg: 'no scopes in token', claims: claims})
        else  
          return callback(true)
  }
  callback(false, {msg: 'token signature did not verify'})
}

var PUBLIC_KEYS = {
}

function getPublicKeyForIssuer(errorHandler, issuerTokenKeyURL, callback) {
    sendExternalRequestThen(errorHandler, 'GET', issuerTokenKeyURL, {accept: 'application/json'}, null, clientRes => {
      getClientResponseBody(clientRes, body => {
        if (clientRes.statusCode == 200) {
          var jso
          try {
            jso = JSON.parse(body)
          }
          catch (err) {
            log('http-helper-functions:getPublicKeyForIssuer', body)
            internalError(errorHandler, {msg: 'invalid JSON in response', err: err, body: body} )
          }
          let keys
          if (jso) {
            let key = jso.value
            if (issuerTokenKeyURL in PUBLIC_KEYS) {
              keys = PUBLIC_KEYS[issuerTokenKeyURL]
              if (keys.length == 2)
                keys.pop()
              keys.unshift(key)
            } else
              keys = PUBLIC_KEYS[issuerTokenKeyURL] = [key]
            callback(keys)
          }
        } else
          internalError(errorHandler, {msg: 'response not JSON: ' % contentType, body: body})
      })
    })
}

function withPublicKeysForIssuerDo(errorHandler, issuerTokenKeyURL, callback) {
  if (issuerTokenKeyURL in PUBLIC_KEYS)
    callback(PUBLIC_KEYS[issuerTokenKeyURL])
  else
    getPublicKeyForIssuer(errorHandler, issuerTokenKeyURL, callback)
}

function refreshPublicKeysForIssuers() {
  log('http-helper-functions:refreshPublicKeysForIssuers', `refreshing token for ${Object.keys(PUBLIC_KEYS)}`)
  let res = errorHandler(err => log('http-helper-functions:refreshPublicKeysForIssuers', `statusCode: ${err.statusCode} body: ${err.body}`))
  for (let issuerTokenKeyURL in PUBLIC_KEYS) {
    getPublicKeyForIssuer(res, issuerTokenKeyURL, (keys) => {})
  }
}

setInterval(refreshPublicKeysForIssuers, TOKEN_KEY_REFERESH_INTERVAL)

function isValidTokenFromIssuer(token, res, issuerTokenKeyURL, scopes, callback) {
  withPublicKeysForIssuerDo(res, issuerTokenKeyURL, (keys) => {
    isValidToken(token, keys, scopes, callback)
  })
}

const SSO_KEY_URL = process.env.AUTH_KEY_URL
const SSO_AUTHORIZATION_URL = process.env.SSO_AUTHORIZATION_URL
const SSO_TOKEN_URL = process.env.AUTH_URL
const OAUTH_CALLBACK_URL = encodeURIComponent(process.env.OAUTH_CALLBACK_URL)
const SSO_CLIENT_ID = encodeURIComponent(process.env.SSO_CLIENT_ID)
const SSO_CLIENT_SECRET = encodeURIComponent(process.env.SSO_CLIENT_SECRET)
const SSO_REDIRECT_URL = `${SSO_AUTHORIZATION_URL}?response_type=code&redirect_uri=${OAUTH_CALLBACK_URL}&client_id=${SSO_CLIENT_ID}`
const SSO_ACCESS_TOKEN_COOKIE = process.env.SSO_ACCESS_TOKEN_COOKIE || 'sso-access-token'
const SSO_REFRESH_TOKEN_COOKIE = process.env.SSO_ACCESS_TOKEN_COOKIE || 'sso-refresh-token'

function getSSOCookies(req, callback) {
  let cookieHeader = req.headers.cookie
  if (cookieHeader) {
    let accessToken, refreshToken
    let cookies = cookieHeader.split(';')
    for (let cookie of cookies) {
      let cookieParts = cookie.split('=')
      let cookieToken = cookieParts[0].trim()
      if (cookieToken == SSO_ACCESS_TOKEN_COOKIE)
        accessToken = cookieParts[1].trim()
      else if (cookieToken == SSO_REFRESH_TOKEN_COOKIE)
        refreshToken = cookieParts[1].trim()
    }
    callback(accessToken, refreshToken)
  } else
    callback (null, null)
}

function redirectToAuthServer(res, refreshURL, scopes) {
  let redirectURL = SSO_REDIRECT_URL + `&state=${encodeURIComponent(refreshURL)}`
  if (scopes)
    for (let scope of scopes)
      redirectURL += `&${scope}`
  let body = `<head><meta http-equiv="refresh" content="0; url=${redirectURL}"></head>\n`
      + `<a href="${redirectURL}">${redirectURL}</a>`
  res.writeHead(401, { location: redirectURL })
  res.end(body)  
}

// 
function getTokensFromCodeThen(errorHandler, code, clientID, clientSecret, tokenURL, callback) {
  var headers = {'content-type': 'application/x-www-form-urlencoded;charset=utf-8', accept: 'application/json;charset=utf-8'}
  var body = `grant_type=authorization_code&client_id=${encodeURIComponent(clientID)}&client_secret=${encodeURIComponent(clientSecret)}&code=${encodeURIComponent(code)}&redirect_uri=${OAUTH_CALLBACK_URL}&response_type=token`
  sendExternalRequestThen(errorHandler, 'POST', tokenURL, headers, body, function(clientRes) {
    getClientResponseBody(clientRes, function(resp_body) {
      if (clientRes.statusCode == 200) {
        let accessToken = JSON.parse(resp_body).access_token
        let refreshToken = JSON.parse(resp_body).refresh_token
        log('getTokensFromCodeThen', `retrieved token for: ${clientID}`)
        callback(accessToken, refreshToken)
      } else {
        log('getTokensFromCodeThen', `unable to retrieve token. tokenURL: ${tokenURL}, headers: ${util.inspect(headers)} body: ${body}`)
        badRequest(errorHandler, {msg: 'unable to retrieve client token', body: resp_body})
      }
    })
  })
}

// 
function refreshTokenFromIssuer(res, refreshToken, clientID, clientSecret, tokenURL, callback) {
  var headers = {'content-type': 'application/x-www-form-urlencoded;charset=utf-8', accept: 'application/json;charset=utf-8'}
  var body = `grant_type=refresh_token&client_id=${encodeURIComponent(clientID)}&client_secret=${encodeURIComponent(clientSecret)}&refresh_token=${refreshToken}`
  sendExternalRequestThen(res, 'POST', tokenURL, headers, body, function(clientRes) {
    getClientResponseBody(clientRes, function(resp_body) {
      if (clientRes.statusCode == 200) {
        let accessToken = JSON.parse(resp_body).access_token
        let refreshToken = JSON.parse(resp_body).refresh_token
        log('refreshTokenFromIssuer', `retrieved token for: ${clientID}`)
        callback(accessToken, refreshToken)
      } else {
        log('refreshTokenFromIssuer', `unable to retrieve token. tokenURL: ${tokenURL}, headers: ${util.inspect(headers)} body: ${body}`)
        callback(null, null)
      }
    })
  })
}

/**
 * Handles the redirect from the Auth Server back to a Resource Server
 * Trades a code for an auth token
 * @param {*} req 
 * @param {*} res 
 */
function authorize(req, res) {
  let parsedURL = url.parse(req.url)
  let queryParts = querystring.parse(parsedURL.query)
  let code = queryParts.code
  let refreshURL = decodeURIComponent(queryParts.state)
  getTokensFromCodeThen(res, code, SSO_CLIENT_ID, SSO_CLIENT_SECRET, SSO_TOKEN_URL, (accessToken, refreshToken) => {
    let setCookies = [`${SSO_ACCESS_TOKEN_COOKIE}=${accessToken}`, `${SSO_REFRESH_TOKEN_COOKIE}=${refreshToken}`]
    res.writeHead(302, { location: refreshURL, 'set-cookie': setCookies })
    res.end()
  })
}

const UNSAFE_METHODS = ['POST', 'PATCH', 'DELETE', 'PUT']
const SAFE_METHODS = ['GET', 'OPTIONS', 'HEAD']

function calculateXsrfHash(user, issueTime) {
  let text = user + ':' + issueTime;
  return createHmac('sha1', XSRF_SECRET).update(text).digest('hex');
}

function calculateXsrfToken(user) {
  let now = Date.now();
  let hash = calculateXsrfHash(user, now);
  let b64 = new Buffer(hash).toString('base64');
  return b64 + ':' + now;
}

function ifXsrfHeaderValidThen(req, res, callback) {
  let notBrowserHost = req.headers.host != BROWSER_ACCESSIBLE_HOST
  let safeMethod = SAFE_METHODS.includes(req.method)
  if (notBrowserHost || safeMethod) {
    callback()
  } else {         
    let xsrfToken = req.headers.xsrfToken;
    if (xsrfToken) {
      let parts = xsrfToken.split(':')
      if (parts.length == 2) {
        let issueTime = parts[1]
        if (issueTime + XSRF_TOKEN_TIMEOUT > Date.now()) {
          let hash = Buffer.from(parts[0], 'base64');
          let expectedHash = calculateXsrfHash(user, issueTime)
          if (expectedHash == hash) {
            callback()
          } else {
            rLib.forbidden(res, {msg: 'invalid xsrf token'})
          }
        } else {
          rLib.forbidden(res, {msg: 'xsrf token expired'})                  
        }
      } else {
        rLib.forbidden(res, {msg: 'invalid xsrf token'})        
      }
    } else {
      rLib.forbidden(res, {msg: 'missing xsrf token'})
    }
  }
}

function validateTokenThen(req, res, scopes, callback) {
  isValidTokenFromIssuer(getToken(req.headers.authorization), res, SSO_KEY_URL, scopes, (isValid, reason) => {
    if (isValid) { 
      // valid token in the authorization header. 
      // if this is a modification request on the host for browsers
      // then the xsrf token must be present and correct
      ifXsrfHeaderValidThen(req, res, () => {
        // If there is an x-client-authorization token it has to be good too 
        let clientToken = getToken(req.headers['x-client-authorization'])
        if (clientToken)
          isValidTokenFromIssuer(clientToken, res, SSO_KEY_URL, scopes, (isValid, reason) => {
            if (isValid) // valid token in the authorization header. Good to go
              callback(true)
            else
              callback(isValid, reason)
          })
        else
          callback(true)
      });
    } else {
      let accept = req.headers.accept;
      if (req.method === 'GET' && accept && accept.startsWith('text/html')) {
        // call from a browser, or something acting like one
        validate_html_get()
      } else {
        let clientToken = getToken(req.headers['x-client-authorization'])
        if (!req.headers.authorization && clientToken)
          isValidTokenFromIssuer(clientToken, res, SSO_KEY_URL, scopes, (isValid, reason) => {
            if (isValid) { 
              // valid token in the x-client-authorization header.
              // Remove the invalid token from the req headers, 
              // so the caller knows only the 'x-client-authorization' is good
              delete req.headers.authorization
              callback(true)
            } else
              callback(isValid, reason)  
          })            
        else
          callback(isValid, reason)
      }
    }
  })
  
  function validate_html_get() {
    getSSOCookies(req, (accessToken, refreshToken) => {
      isValidTokenFromIssuer(accessToken, res, SSO_KEY_URL, scopes, (isValid, reason) => {
        if (isValid) { // valid token in the cookie. Good to go
          req.headers.authorization = `Bearer ${accessToken}`
          callback(true)
        } else
          if (refreshToken)
            refreshTokenFromIssuer(res, refreshToken, SSO_CLIENT_ID, SSO_CLIENT_SECRET, SSO_TOKEN_URL, (accessToken, refreshToken) => {
              if (accessToken) {
                req.headers.authorization = `Bearer ${accessToken}`
                let setCookies = [`${SSO_ACCESS_TOKEN_COOKIE}=${accessToken}`, `${SSO_REFRESH_TOKEN_COOKIE}=${refreshToken}`]
                res.setHeader('set-cookie', setCookies)
                isValidTokenFromIssuer(accessToken, res, SSO_KEY_URL, scopes, (isValid, reason) => {
                  if (isValid) // valid token in the refreshed token. Good to go
                    callback(true)
                  else 
                    redirectToAuthServer(res, req.url, scopes)
                })
              } else
                redirectToAuthServer(res, req.url, scopes)
            })
          else 
            redirectToAuthServer(res, req.url, scopes) 
      })
    })
  }
}

function getEmailFromToken(token) {
  var claims = getClaimsFromToken(token)
  return claims == null ? null : ((typeof `${claims.email}`) == 'undefined' ? '' : claims.email)
}

function getEmail(auth) {
  return getEmailFromToken(getToken(auth))
}

function getContext(req) {
  var context = req.context
  if (!context)
    req.context = context = {
      user: getUser(req.headers.authorization),
      'request-id': req.headers['x-request-id']
    }
  return context
}

exports.getEmailFromToken = getEmailFromToken
exports.getEmail = getEmail
exports.getServerPostObject = getServerPostObject
exports.getServerPostBuffer = getServerPostBuffer
exports.getClientResponseBody = getClientResponseBody
exports.getClientResponseBuffer = getClientResponseBuffer
exports.methodNotAllowed = methodNotAllowed
exports.notFound = notFound
exports.badRequest = badRequest
exports.duplicate = duplicate
exports.found = found
exports.created = created
exports.respond = respond
exports.internalizeURL = internalizeURL
exports.internalizeURLs = internalizeURLs
exports.externalizeURLs = externalizeURLs
exports.getUser = getUser
exports.getScopes = getScopes
exports.getToken = getToken
exports.forbidden = forbidden
exports.unauthorized = unauthorized
exports.applyPatch = applyPatch
exports.internalError = internalError
exports.setStandardCreationProperties = setStandardCreationProperties
exports.getUserFromToken = getUserFromToken
exports.sendInternalRequestThen=sendInternalRequestThen
exports.sendInternalRequest=sendInternalRequest
exports.toHTML=toHTML
exports.uuid4 = uuid4
exports.getHostIPThen = getHostIPThen
exports.sendExternalRequest = sendExternalRequest
exports.sendExternalRequestThen = sendExternalRequestThen
exports.flowThroughHeaders = flowThroughHeaders
exports.withInternalResourceDo = withInternalResourceDo
exports.patchInternalResourceThen = patchInternalResourceThen
exports.postToInternalResourceThen = postToInternalResourceThen
exports.deleteInternalResourceThen = deleteInternalResourceThen
exports.getClientResponseObject = getClientResponseObject
exports.withValidClientToken = withValidClientToken
exports.validateTokenThen = validateTokenThen
exports.authorize = authorize
exports.getContext = getContext
exports.normalizeURLPart = normalizeURLPart
exports.normalizeURL = normalizeURL
exports.withExternalResourceDo = withExternalResourceDo
exports.patchExternalResourceThen = patchExternalResourceThen
exports.postToExternalResourceThen = postToExternalResourceThen

// exported for testing only
exports.isValidTokenFromIssuer = isValidTokenFromIssuer
