'use strict'
const http = require('http')
const https = require('https')
const jsonpatch= require('./jsonpatch')
const randomBytes = require('crypto').randomBytes
const createVerify = require('crypto').createVerify
const url = require('url')
const util = require('util')
const httpKeepAliveAgent = new http.Agent({ keepAlive: true })
const httpsKeepAliveAgent = new https.Agent({ keepAlive: true })

const INTERNAL_SCHEME = process.env.INTERNAL_SCHEME || 'http'
const INTERNAL_PROTOCOL = INTERNAL_SCHEME + ':'
const INTERNALURLPREFIX = ''
const INTERNAL_SY_ROUTER_PORT = process.env.INTERNAL_SY_ROUTER_PORT
const SHIPYARD_PRIVATE_SECRET = process.env.SHIPYARD_PRIVATE_SECRET !== undefined ? new Buffer(process.env.SHIPYARD_PRIVATE_SECRET).toString('base64') : undefined
const MIN_TOKEN_VALIDITY_PERIOD = process.env.MIN_TOKEN_VALIDITY_PERIOD || 5000
const CHECK_PERMISSIONS = process.env.CHECK_PERMISSIONS == 'false' ? false : true
const CHECK_IDENTITY = CHECK_PERMISSIONS || (process.env.CHECK_IDENTITY == 'true')
const RUNNING_BEHIND_APIGEE_EDGE = process.env.RUNNING_BEHIND_APIGEE_EDGE == 'true'
const TOKEN_KEY_REFERESH_INTERVAL = process.env.TOKEN_KEY_REFERESH_INTERVAL ? parseInt(process.env.TOKEN_KEY_REFERESH_INTERVAL) : 5*60*1000 // 5 min refresh
const fs = require('fs')

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

function fixUpHeadersAndBody(headers, body) {
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

function sendInternalRequest(method, pathRelativeURL, headers, body, callback) {
  if (pathRelativeURL.startsWith('//')) // amazingly, url.parse parses URLs that begin with // wrongly
    pathRelativeURL = url.parse(INTERNAL_PROTOCOL + pathRelativeURL).path
  else
    pathRelativeURL = url.parse(pathRelativeURL).path
  if (typeof headers == 'function') {
    callback = headers
    headers = {}
  }
  var id = generateIdentifier()
  log('http-helper-functions:sendInternalRequest', `id: ${id} method: ${method} hostname: ${process.env.INTERNAL_SY_ROUTER_HOST}${INTERNAL_SY_ROUTER_PORT ? `:${INTERNAL_SY_ROUTER_PORT}` : ''} url: ${pathRelativeURL}`)
  body = fixUpHeadersAndBody(headers, body)
  if (SHIPYARD_PRIVATE_SECRET !== undefined)
    headers['x-routing-api-key'] = SHIPYARD_PRIVATE_SECRET
  var options = {
    protocol: INTERNAL_PROTOCOL,
    hostname: process.env.INTERNAL_SY_ROUTER_HOST,
    path: pathRelativeURL,
    method: method,
    headers: headers,
    agent: keepAliveAgent(INTERNAL_PROTOCOL)
  }
  if (INTERNAL_SY_ROUTER_PORT)
    options.port = INTERNAL_SY_ROUTER_PORT
  var clientReq = (INTERNAL_SCHEME == 'https' ? https : http).request(options, function(clientRes) {
    log('http-helper-functions:sendInternalRequest', `id: ${id} received response after ${Date.now() - startTime} millisecs. method: ${method} hostname: ${process.env.INTERNAL_SY_ROUTER_HOST}${INTERNAL_SY_ROUTER_PORT ? `:${INTERNAL_SY_ROUTER_PORT}` : ''} url: ${pathRelativeURL}`)
    callback(null, clientRes)
  })
  var startTime = Date.now()
  clientReq.setTimeout(300000, () => {
    var msg = `socket timeout after ${Date.now() - startTime} millisecs pathRelativeURL: ${pathRelativeURL}`
    log('http-helper-functions:sendInternalRequest', `id: ${id} socket timeout after ${Date.now() - startTime} millisecs. pathRelativeURL: ${pathRelativeURL}`)
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

function sendInternalRequestThen(res, method, pathRelativeURL, headers, body, callback) {
  if (typeof headers == 'function')
    [callback, headers] = [headers, {}]
  else if (headers == null)
    headers = {}
  sendInternalRequest(method, pathRelativeURL, headers, body, function(errStr, clientRes) {
    if (errStr) {
      var err = {
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

function withInternalResourceDo(res, pathRelativeURL, headers, callback) {
  sendInternalRequestThen(res, 'GET', pathRelativeURL, headers, null, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, body => {
      if (clientRes.statusCode == 200)
        callback(body, clientRes)
      else
        internalError(res, {msg: 'unable to retrieve internal resource', url: pathRelativeURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

function patchInternalResourceThen(res, pathRelativeURL, headers, patch, callback) {
  sendInternalRequestThen(res, 'PATCH', pathRelativeURL, headers, patch, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, body => {
      if (clientRes.statusCode == 200)
        callback(body, clientRes)
      else
        internalError(res, {msg: 'unable to patch internal resource', url: pathRelativeURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

function postToInternalResourceThen(res, pathRelativeURL, headers, requestBody, callback) {
  sendInternalRequestThen(res, 'POST', pathRelativeURL, headers, requestBody, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, responseBody => {
      if (Math.floor(clientRes.statusCode / 100) == 2)
        callback(responseBody, clientRes)
      else
        internalError(res, {msg: 'unable to post to internal resource', url: pathRelativeURL, statusCode: clientRes.statusCode, responseBody: responseBody})
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
  body = fixUpHeadersAndBody(headers, body)
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
        internalError(errorHandler, {msg: 'response not JSON: ' % contentType, body: body})
  })
}

function getClientResponseBuffer(res, callback) {
  var body = []
  res.on('data', chunk => body.push(chunk))
  res.on('end', () => callback(Buffer.concat(body)))
}

function getClaims(token) {
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
  var claims = getClaims(token)
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

function getScopes(auth) {
  let claims = getClaims(getToken(auth));
  return claims !== null && claims !== undefined && claims.scope ? claims.scope : []
}

function methodNotAllowed(req, res, allow) {
  var body = 'Method not allowed. request-target: ' + req.url + ' method: ' + req.method + '\n'
  body = JSON.stringify(body)
  res.writeHead(405, {'content-type': 'application/json',
                      'content-length': Buffer.byteLength(body),
                      'allow': allow.join(', ') })
  res.end(body)
}

function notFound(req, res, body) {
  body = body || `Not Found. component: ${process.env.COMPONENT_NAME} request-target: //${req.headers.host}${req.url} method: ${req.method}\n`
  body = JSON.stringify(body)
  res.writeHead(404, {'content-type': 'application/json',
                      'content-length': Buffer.byteLength(body)})
  res.end(body)
}

function forbidden(req, res, body) {
  body = body || `Forbidden. component: ${process.env.COMPONENT_NAME} request-target: //${req.headers.host}${req.url} method: ${req.method} user: ${getUser(req.headers.authorization)}\n`
  body = JSON.stringify(body)
  res.writeHead(403, {'content-type': 'application/json',
                      'content-length': Buffer.byteLength(body)})
  res.end(body)
}

function unauthorized(req, res, body) {
  body = body || 'Unauthorized. request-target: ' + req.url
  body = JSON.stringify(body)
  res.writeHead(401, {'content-type': 'application/json',
                      'content-length': Buffer.byteLength(body)})
  res.end(body)
}

function badRequest(res, err) {
  var body = JSON.stringify(err)
  res.writeHead(400, {'content-type': 'application/json',
                      'content-length': Buffer.byteLength(body)})
  res.end(body)
}

function internalError(res, err) {
  var body = JSON.stringify(err)
  res.writeHead(500, {'content-type': 'application/json',
                      'content-length': Buffer.byteLength(body)})
  res.end(body)
}

function duplicate(res, err) {
  var body = JSON.stringify(err)
  res.writeHead(409, {'content-type': 'application/json',
                      'content-length': Buffer.byteLength(body)})
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
    headers['content-length'] = Buffer.byteLength(body)
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
function withValidClientToken(errorHandler, token, clientID, clientSecret, authURL, callback) {
  if (CHECK_PERMISSIONS || CHECK_IDENTITY) {
    var claims = getClaims(token)
    if (claims != null && (claims.exp * 1000) > Date.now() + MIN_TOKEN_VALIDITY_PERIOD)
      callback()
    else {
      var headers = {'content-type': 'application/x-www-form-urlencoded;charset=utf-8', accept: 'application/json;charset=utf-8'}
      var body = `grant_type=client_credentials&client_id=${clientID}&client_secret=${clientSecret}`
      sendExternalRequestThen(errorHandler, 'POST', authURL, headers, body, function(clientRes) {
        getClientResponseBody(clientRes, function(resp_body) {
          if (clientRes.statusCode == 200) {
            token = JSON.parse(resp_body).access_token
            log('withValidClientToken', `retrieved token for: ${clientID}`)
            callback(token)
          } else {
            log('withValidClientToken', `unable to retrieve token. authURL: ${authURL}, headers: ${util.inspect(headers)}`)
            badRequest(errorHandler, {msg: 'unable to retrieve client token', body: resp_body})
          }
        })
      })
    }
  } else
    callback()
}

function isValidToken(token, publicKeys, callback) {
  if (publicKeys.length == 0)
    return callback(false, 'no keys provided')
  if (typeof token != 'string')
    return callback(false, 'no token provided')    
  let tokenParts = token.split('.')
  if (tokenParts.length != 3)
    return callback(false, 'malformed token')
  let header = JSON.parse(Buffer.from(tokenParts[0], 'base64').toString())
  if (header.alg != 'RS256')
    return callback(false, `token alg must be 'RS256', found ${header.alg}`)
  let claims = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString())
  let signature = tokenParts[2]
  let signedPart = token.substring(0, token.length - signature.length - 1)
  for (let i = 0; i< publicKeys.length; i++) {
    let verified = createVerify('RSA-SHA256').update(signedPart).verify(publicKeys[i], signature, 'base64')
    if (verified)
      if (claims.nbf && Date.now() < claims.nbf*1000) 
        return callback(false, 'token not yet valid')
      else if (claims.exp && Date.now() > claims.exp*1000)
        return callback(false, 'token expired')
      else
        return callback(verified)
  }
  callback(false, 'token signature did not verify')
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

function isValidTokenFromIssuer(req, res, issuerTokenKeyURL, callback) {
  withPublicKeysForIssuerDo(res, issuerTokenKeyURL, keys => isValidToken(getToken(req.headers.authorization), keys, callback))
}

function getEmailFromToken(token) {
  var claims = getClaims(token)
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
exports.getClaims = getClaims
exports.getScopes = getScopes
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
exports.getClientResponseObject = getClientResponseObject
exports.withValidClientToken = withValidClientToken
exports.getContext = getContext
exports.normalizeURLPart = normalizeURLPart
exports.normalizeURL = normalizeURL
exports.isValidTokenFromIssuer = isValidTokenFromIssuer
