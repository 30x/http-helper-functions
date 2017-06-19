'use strict'
const http = require('http')
const https = require('https')
const jsonpatch= require('./jsonpatch')
const randomBytes = require('crypto').randomBytes
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
const CHECK_IDENTITY = CHECK_PERMISSIONS || (process.env.CHECK_IDENTITY == 'true' ? true : false)
const fs = require('fs')

function log(funcionName, text) {
  console.log(new Date().toISOString(), process.env.COMPONENT_NAME, funcionName, text)
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
  }  
  return body
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
  log('http-helper-functions:sendInternalRequest', `method: ${method} hostname: ${process.env.INTERNAL_SY_ROUTER_HOST}${INTERNAL_SY_ROUTER_PORT ? `:${INTERNAL_SY_ROUTER_PORT}` : ''} url: ${pathRelativeURL}`)
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
    callback(null, clientRes)
  })
  var startTime = Date.now()
  clientReq.setTimeout(300000, () => {
    var msg = `socket timeout after ${Date.now() - startTime} millisecs pathRelativeURL: ${pathRelativeURL}`
    log('http-helper-functions:sendInternalRequest', `socket timeout after ${Date.now() - startTime} millisecs pathRelativeURL: ${pathRelativeURL}`)
    clientReq.abort()
    callback(msg)
  })
  clientReq.on('error', function (err) {
    var the_options = Object.assign({}, options)
    delete the_options.agent
    log('http-helper-functions:sendInternalRequest', `error ${err} options: options: ${JSON.stringify(the_options)}`)
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
      log('http-helper-functions:sendInternalRequestThen', `error ${err} method ${method} host: ${headers.host} path ${pathRelativeURL} headers ${JSON.stringify(headers)}`)
      internalError(res, err)
    } else 
      callback(clientRes)
  })
}

function withInternalResourceDo(res, pathRelativeURL, headers, callback) {
  sendInternalRequestThen(res, 'GET', pathRelativeURL, headers, null, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, body => {
      if (clientRes.statusCode == 200)
        callback(body)
      else
        internalError(res, {msg: 'unable to retrieve internal resource', url: pathRelativeURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

function patchInternalResourceThen(res, pathRelativeURL, headers, patch, callback) {
  sendInternalRequestThen(res, 'PATCH', pathRelativeURL, headers, patch, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, body => {
      if (clientRes.statusCode == 200)
        callback(body)
      else
        internalError(res, {msg: 'unable to patch internal resource', url: pathRelativeURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

function postToInternalResourceThen(res, pathRelativeURL, headers, requestBody, callback) {
  sendInternalRequestThen(res, 'POST', pathRelativeURL, headers, requestBody, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, responseBody => {
      if (Math.floor(clientRes.statusCode / 100) == 2)
        callback(responseBody)
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
  return headers
}

function sendExternalRequest(method, targetUrl, headers, body, callback) {
  if (typeof headers == 'function') {
    callback = headers
    headers = {}
  }
  log('http-helper-functions:sendExternalRequest', `method: ${method} url: ${targetUrl}`)
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
    callback(null, clientRes)
  })
  var startTime = Date.now()
  clientReq.setTimeout(300000, () => {
    var msg = `socket timeout after ${Date.now() - startTime} millisecs pathRelativeURL: ${pathRelativeURL}`
    log('http-helper-functions:sendExternalRequest', `socket timeout after ${Date.now() - startTime} millisecs pathRelativeURL: ${pathRelativeURL}`)
    clientReq.abort()
    callback(msg)
  })
  clientReq.on('error', function (err) {
    log('http-helper-functions:sendExternalRequest', `url: ${targetUrl} ${err}`)
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
        log('http-helper-functions:getServerPostObject', body)
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
          internalError(errorHandler, `invalid JSON: ${err.message} body: ${body}` )
        }
        if (jso)
          callback(internalizeURLs(jso, host, contentType))
      } else
        internalError(errorHandler, 'response not JSON: ' % contentType)
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
  body = JSON.stringify(body)
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
    if (!('Content-Type' in headers))
      headers['Content-Type'] = contentType ? contentType : wantsHTML ? 'text/html' : 'application/json'
    externalizeURLs(body, req.headers.host)
    var contentType = headers['Content-Type']
    body = body instanceof Buffer ? body : contentType == 'text/html' ? toHTML(body) : contentType == 'text/plain' ? body.toString() : contentType == 'application/json' ? JSON.stringify(body) : body.toString()
    headers['Content-Length'] = Buffer.byteLength(body)
    res.writeHead(status, headers)
    res.end(body)
  } else { 
    res.writeHead(status, headers)
    res.end()
  }
}

function internalizeURL(anURL, authority) {
  var decodedURL = decodeURIComponent(anURL)
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
    else if (typeof jsObject == 'string' && (jsObject.startsWith('http') || jsObject.startsWith('/') || jsObject.startsWith('%2F')) && jsObject.match(re))
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
        return badRequest(res, `err: ${err} patch: ${JSON.stringify(patch)}`)
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
            log('withValidClientToken', `unable to retrieve token. authURL: ${authURL}, headers: ${JSON.stringify(headers)}`)
            badRequest(errorHandler, {msg: 'unable to retrieve client token', body: resp_body})
          }
        })
      })
    }
  } else
    callback()
}

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