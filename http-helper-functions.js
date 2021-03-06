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
const path = require('path')

const INTERNAL_SCHEME = process.env.INTERNAL_SCHEME || 'http'
const INTERNAL_PROTOCOL = INTERNAL_SCHEME + ':'
const INTERNALURLPREFIX = ''
const INTERNAL_SY_ROUTER_PORT = process.env.INTERNAL_SY_ROUTER_PORT
const INTERNAL_SY_ROUTER_HOST = process.env.INTERNAL_SY_ROUTER_HOST
const SHIPYARD_PRIVATE_SECRET = process.env.SHIPYARD_PRIVATE_SECRET !== undefined ? new Buffer(process.env.SHIPYARD_PRIVATE_SECRET).toString('base64') : undefined
const MIN_TOKEN_VALIDITY_PERIOD = process.env.MIN_TOKEN_VALIDITY_PERIOD || 10000
const CHECK_PERMISSIONS = process.env.CHECK_PERMISSIONS !== 'false';
const CHECK_IDENTITY = CHECK_PERMISSIONS || (process.env.CHECK_IDENTITY == 'true')
const RUNNING_BEHIND_APIGEE_EDGE = process.env.RUNNING_BEHIND_APIGEE_EDGE == 'true'
const TOKEN_KEY_REFERESH_INTERVAL = process.env.TOKEN_KEY_REFERESH_INTERVAL ? parseInt(process.env.TOKEN_KEY_REFERESH_INTERVAL) : 5*60*1000 // 5 min refresh

const BROWSER_ACCESSIBLE_HOST = process.env.BROWSER_ACCESSIBLE_HOST
const XSRF_SECRET = process.env.XSRF_SECRET
const XSRF_TOKEN_TIMEOUT = process.env.XSRF_SECRET || 2*60*60*1000 // 2 hrs

// support MAX_RECORD_SIZE env variable; default to 1e6 (1MB) if the input in not a number
let configuredMaxRecordSize = parseInt(process.env.MAX_RECORD_SIZE, 10)
const MAX_RECORD_SIZE = isNaN(configuredMaxRecordSize) ? 1e6 : configuredMaxRecordSize
const CLIENT_REQUEST_TIMEOUT = isNaN(parseInt(process.env.CLIENT_REQUEST_TIMEOUT, 10)) ? 60 * 1000 : parseInt(process.env.CLIENT_REQUEST_TIMEOUT, 10)

function log(functionName, text) {
  console.log(new Date().toISOString(), process.env.COMPONENT_NAME, functionName, text)
}

function keepAliveAgent(protocol) {
  return protocol == 'https:' ? httpsKeepAliveAgent : httpKeepAliveAgent
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

function sendRequest(method, resourceURL, headers, body, callback) {
  if (typeof headers == 'function')
    [callback, headers] = [headers, {}]
  let parsedURL = resourceURL.startsWith('//') ? url.parse(INTERNAL_PROTOCOL + resourceURL) : url.parse(resourceURL) // amazingly, url.parse parses URLs that begin with // wrongly
  let hostname = parsedURL.host == null ? INTERNAL_SY_ROUTER_HOST : parsedURL.hostname
  let port = parsedURL.host == null ? INTERNAL_SY_ROUTER_PORT : parsedURL.port
  let protocol = parsedURL.protocol == null ? INTERNAL_PROTOCOL : parsedURL.protocol
  let pathRelativeURL = parsedURL.path
  let id = generateIdentifier()
  let msgPrefix = `id: ${id} method: ${method} hostname: ${hostname}${port ? `:${port}` : ''} url: ${pathRelativeURL}`
  log('http-helper-functions:sendRequest', `${msgPrefix} request`)
  body = setContentWithLengthAndType(headers, body)
  if (!'host' in headers)
    headers.host = hostname
  var options = {
    protocol: protocol,
    hostname: hostname,
    path: pathRelativeURL,
    method: method,
    headers: headers,
//    agent: keepAliveAgent(protocol)
  }
  if (port)
    options.port = port
  var startTime = Date.now()
  var clientReq = (protocol == 'https:' ? https : http).request(options, function(clientRes) {
    log('http-helper-functions:sendRequest', `${msgPrefix} response after ${Date.now() - startTime} millisecs`)
    callback(null, clientRes)
  })
  clientReq.setTimeout(CLIENT_REQUEST_TIMEOUT, () => {
    clientReq.abort()
    // Node will also generate an error, which will be logged below and the callback executed
  })
  clientReq.on('error', function (err) {
    log('http-helper-functions:sendRequest', `${msgPrefix} error ${err}`)
    callback(err)
  })
  if (body)
    clientReq.write(body)
  clientReq.end()
}

function sendRequestThen(res, method, resourceURL, headers, body, callback) {
  if (typeof headers == 'function')
    [callback, headers] = [headers, {}]
  else if (headers == null)
    headers = {}
  sendRequest(method, resourceURL, headers, body, function(errStr, clientRes) {
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
      log('http-helper-functions:sendRequestThen', `error ${err} method ${method} host: ${headers.host} path ${pathRelativeURL}}`)
      internalError(res, {msg: 'unable to send  request', err: err, method: method, host: headers.host, path: pathRelativeURL})
    } else
      callback(clientRes)
  })
}

// Kept for backwards compatibility
function sendInternalRequest(method, resourceURL, headers, body, callback) {
  sendRequest(method, resourceURL, headers, body, callback)
}

// Kept for backwards compatibility
function sendInternalRequestThen(res, method, resourceURL, headers, body, callback) {
  sendRequestThen(res, method, resourceURL, headers, body, callback)
}

function withResourceDo(res, resourceURL, headers, callback) {
  if (!headers.accept)
    headers.accept = 'application/json'
  sendRequestThen(res, 'GET', resourceURL, headers, null, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, body => {
      if (clientRes.statusCode == 200)
        callback(body, clientRes)
      else
        internalError(res, {msg: 'unable to retrieve internal resource', url: resourceURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

// Kept for backwards compatibility
function withInternalResourceDo(res, resourceURL, headers, callback) {
  withResourceDo(res, resourceURL, headers, callback)
}

function patchResourceThen(res, resourceURL, headers, patch, callback) {
  if (!headers.accept)
    headers.accept = 'application/json'
  sendRequestThen(res, 'PATCH', resourceURL, headers, patch, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, body => {
      if (clientRes.statusCode == 200)
        callback(body, clientRes)
      else
        internalError(res, {msg: 'unable to patch internal resource', url: resourceURL, statusCode: clientRes.statusCode, body: body})
    })
  })
}

// Kept for backwards compatibility
function patchInternalResourceThen(res, resourceURL, headers, patch, callback) {
  patchResourceThen(res, resourceURL, headers, patch, callback)
}

function deleteResourceThen(res, resourceURL, headers, callback) {
  if (!headers.accept)
    headers.accept = 'application/json'
  sendRequestThen(res, 'DELETE', resourceURL, headers, null, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, responseBody => {
      if (Math.floor(clientRes.statusCode / 100) == 2)
        callback(responseBody, clientRes)
      else
        internalError(res, {msg: 'unable to post to internal resource', url: resourceURL, statusCode: clientRes.statusCode, responseBody: responseBody})
    })
  })
}

// Kept for backwards compatibility
function deleteInternalResourceThen(res, resourceURL, headers, callback) {
  deleteResourceThen(res, resourceURL, headers, callback)
}

function postToResourceThen(res, resourceURL, headers, requestBody, callback) {
  if (!headers.accept)
    headers.accept = 'application/json'
  sendRequestThen(res, 'POST', resourceURL, headers, requestBody, function(clientRes) {
    getClientResponseObject(res, clientRes, headers.host, responseBody => {
      if (Math.floor(clientRes.statusCode / 100) == 2)
        callback(responseBody, clientRes)
      else
        respond({headers: {}}, res, clientRes.statusCode, {}, responseBody)
    })
  })
}

// Kept for backwards compatibility
function postToInternalResourceThen(res, resourceURL, headers, requestBody, callback) {
  postToResourceThen(res, resourceURL, headers, requestBody, callback)
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

// Kept for backwards compatibility
function sendExternalRequest(method, targetUrl, headers, body, callback) {
  sendRequest(method, targetUrl, headers, body, callback)
}

// Kept for backwards compatibility
function sendExternalRequestThen(res, method, targetUrl, headers, body, callback) {
  sendRequestThen(res, method, targetUrl, headers, body, callback)
}

// Kept for backwards compatibility
function withExternalResourceDo(res, resourceURL, headers, callback) {
  withResourceDo(res, resourceURL, headers, callback)
}

// Kept for backwards compatibility
function patchExternalResourceThen(res, resourceURL, headers, patch, callback) {
  patchResourceThen(res, resourceURL, headers, patch, callback)
}

// Kept for backwards compatibility
function postToExternalResourceThen(res, resourceURL, headers, requestBody, callback) {
  postToResourceThen(res, resourceURL, headers, requestBody, callback)
}

function getServerPostObject(req, res, callback) {
  var body = ''
  req.on('data', function (data) {
    if (body.length + data.length > MAX_RECORD_SIZE)
      return req.connection.destroy()
    body += data
  })
  req.on('end', function () {
    var contentType = req.headers['content-type']
    if (contentType === undefined || (contentType.startsWith('application/', 0) && contentType.endsWith('json'))) {
      var jso
      try {
        jso = JSON.parse(body)
      }
      catch (err) {
        log('http-helper-functions:getServerPostObject', `invalid JSON: ${err.message} body: ${body}`)
        badRequest(req, res, `invalid JSON: ${err.message} body: ${body}` )
      }
      if (jso !== undefined)
        callback(internalizeURLs(jso, req.headers.host, contentType))
    } else
      badRequest(req, res, 'input must be JSON')
  })
}

function getServerPostBuffer(req, callback) {
  var body = []
  req.on('data', function (data) {
    if (body.reduce((total, item) => total + item.length, 0) + data.length > MAX_RECORD_SIZE)
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
    if (contentType !== undefined)
      contentType = contentType.split(';')[0]
    if (contentType === undefined || (contentType.startsWith('application/', 0) && contentType.endsWith('json')))
      if (body == '')
        callback()
      else {
        var jso
        try {
          jso = JSON.parse(body)
        }
        catch (err) {
          log('http-helper-functions:getClientResponseObject', `invalid JSON: ${err.message} body: ${body}`)
          return internalError(errorHandler, {msg: 'invalid JSON in response', err: err, body: body} )
        }
        callback(internalizeURLs(jso, host, contentType))
      }
    else
      internalError(errorHandler, {msg: 'response content-type not JSON', headers: res.headers, body: body})
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
    token = req.__xxx_token__ = getToken(req.headers.authorization);
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

function methodNotAllowed(req, res, allow, body) {
  body = body || {msg: 'Method not allowed'}
  body = JSON.stringify(body)
  res.writeHead(405, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body),
                      'Allow': allow.join(', ') })
  res.end(body)
}

function notFound(req, res, body) {
  body = body || (req ? {
    msg: 'Not Found',
    component: process.env.COMPONENT_NAME,
    url: req.url,
    host: req.headers.host
  } : {
    msg: 'Not Found',
    component: process.env.COMPONENT_NAME
  })
  body = JSON.stringify(body)
  res.writeHead(404, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function forbidden(req, res, body) {
  body = body || (req ? {
    msg: 'Forbidden',
    component: process.env.COMPONENT_NAME,
    url: req.url,
    host: req.headers.host,
    method: req.method,
    user: getUserFromReq(req)
  } : {
    msg: 'Forbidden',
    component: process.env.COMPONENT_NAME
  })
  body = JSON.stringify(body)
  res.writeHead(403, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function unauthorized(req, res, body) {
  body = body || (req ? {
    msg: 'Unauthorized',
    url: req.url,
    host: req.headers.host
  } : {msg: 'Unauthorized'})
  body = typeof body == 'object' ? JSON.stringify(body) : body
  res.writeHead(401, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function badRequest(req, res, err) {
  err = err || (req ? {
    msg: 'bad request',
    url: req.url,
    host: req.headers.host
  } : {msg: 'bad request'})
  var body = JSON.stringify(err)
  res.writeHead(400, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function internalError(res, err) {
  err = err || {msg: 'internal error'}
  var body = JSON.stringify(err)
  log('http-helper-functions:internalError', body)
  res.writeHead(500, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}

function duplicate(res, err) {
  err = err || {msg: 'duplicate'}
  var body = JSON.stringify(err)
  res.writeHead(409, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
}


/**
 *
 * @param {http.Request} req
 * @param {http.Response} res
 * @param {string, Buffer or object} body
 * @param {string} contentLocation
 * @param {string} etag
 * @param {string} bodyType - the caller may indicate what sort of object is in the body. For example, if the
 *                            body is a JSON-PATCH, then this will need to be refected in the media type if
 *                            we return JSON to the caller. bodyType is conceptually the 'class' of the object
 *                            not the media type that it will be serialized to, but we use the same values for both
 */
function found(req, res, body, contentLocation, etag, bodyType) {
  var headers = {}
  if (contentLocation !== undefined)
    headers['Content-Location'] = contentLocation
  else
    if (req)
      headers['Content-Location'] = req.url
  if (etag !== undefined)
    headers['Etag'] = etag
  respond(req, res, 200, headers, body, bodyType)
}

/**
 *
 * @param {http.Request} req
 * @param {http.Response} res
 * @param {string, Buffer or object} body
 * @param {string} location
 * @param {string} etag
 * @param {string} bodyType - the caller may indicate what sort of object is in the body. For example, if the
 *                            body is a JSON-PATCH, then this will need to be refected in the media type if
 *                            we return JSON to the caller. bodyType is conceptually the 'class' of the object
 *                            not the media type that it will be serialized to, but we use the same values for both
 */
function created(req, res, body, location, etag, bodyType) {
  var headers =  {}
  if (location !== undefined)
    headers['Location'] = location
  if (etag !== undefined)
    headers['Etag'] = etag
  respond(req, res, 201, headers, body, bodyType)
}

/**
 *
 * @param {http.Request} req
 * @param {http.Response} res
 * @param {integer} status
 * @param {object} headers
 * @param {string, Buffer or object} body
 * @param {string} bodyType - the caller may indicate what sort of object is in the body. For example, if the
 *                            body is a JSON-PATCH, then this will need to be refected in the media type if
 *                            we return JSON to the caller. bodyType is conceptually the 'class' of the object
 *                            not the media type that it will be serialized to, but we use the same values for both
 */
function respond(req, res, status, headers, body, bodyType='application/json') {
  if (body !== undefined) {
    if (!(body instanceof Buffer)) {
      let mediaRange = 'application/json'
      if (req && req.headers.accept) {
        let acceptMediaRange = req.headers.accept.split(';')[0]
        if (acceptMediaRange == '*/*' || 
            acceptMediaRange == 'application/*' || 
            (acceptMediaRange.startsWith('application/') && acceptMediaRange.endsWith('json')))
          mediaRange = 'application/json'
        else
          mediaRange = acceptMediaRange
      }
      let wantsHTML = mediaRange.startsWith('text/html')
      let wantsJson = mediaRange.startsWith('application/json')
      if (Object.keys(headers).filter(getContentTypeFilter).length === 0) {
        headers['Content-Type'] = wantsHTML ? 'text/html' : wantsJson ? bodyType : 'text/plain'
      }
      body = wantsHTML ? toHTML(body) : JSON.stringify(body)
    }
    headers['Content-Length'] = Buffer.byteLength(body)
  }
  res.writeHead(status, headers)
  res.end(body)
}

function getContentTypeFilter(element, index, array) {
  return element.toString().toLowerCase() === 'content-type';
}

function preconditionFailed(req, res, err) {
  err = err || {msg: 'precondition failed'}
  var body = JSON.stringify(err)
  res.writeHead(412, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)})
  res.end(body)
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
        return badRequest(null, res, `err: ${err} patch: ${util.inspect(patch)}`)
      }
      callback(patchedDoc, reqHeaders['content-type'])
    }
    else
      badRequest(null, res, `unknown PATCH content-type: ${reqHeaders['content-type']}`)
  else
    badRequest(null, res, 'PATCH headers missing content-type for patch')
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

function setStandardModificationProperties(req, resource, user) {
  resource.modifier = user
  resource.modified = new Date().toISOString()
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

const words = fs.readFileSync(path.join(__dirname, '65536words'), 'utf-8').split('\n')
function uuidw(bytesOfRandom = 16, numberOfWords = 2) {
  var buf = randomBytes(bytesOfRandom), rslt = '', bytesOfWords = numberOfWords*2
  if (bytesOfWords > bytesOfRandom)
    throw Error('numberOfWords * 2 must be <= bytesOfRandom')
  for (let i = 0; i < bytesOfWords; i+=2) {
    if (i>0)
      rslt += '-'
    rslt +=  words[buf[i] * 256 + buf[i+1]]
  }
  if (bytesOfRandom > bytesOfWords) {
    if (numberOfWords > 0)
      rslt += '-'
    for (let i = bytesOfWords; i < bytesOfRandom; i++)
      rslt += toHex[buf[i]]
  }
  return rslt
}

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
  if (CHECK_IDENTITY) {
    var claims = getClaimsFromToken(token)
    if (claims != null && (claims.exp * 1000) > Date.now() + MIN_TOKEN_VALIDITY_PERIOD)
      callback()
    else {
      var headers = {'content-type': 'application/x-www-form-urlencoded;charset=utf-8', accept: 'application/json;charset=utf-8'}
      var body = `grant_type=client_credentials&client_id=${encodeURIComponent(clientID)}&client_secret=${encodeURIComponent(clientSecret)}`
      sendRequestThen(errorHandler, 'POST', tokenURL, headers, body, function(clientRes) {
        getClientResponseBody(clientRes, function(resp_body) {
          if (clientRes.statusCode == 200) {
            token = JSON.parse(resp_body).access_token
            log('withValidClientToken', `retrieved token for: ${clientID}`)
            callback(token)
          } else {
            log('withValidClientToken', `unable to retrieve token. tokenURL: ${tokenURL}, headers: ${util.inspect(headers)}`)
            badRequest(null, errorHandler, {msg: 'unable to retrieve client token', body: resp_body, url: tokenURL, clientID: encodeURIComponent(clientID)})
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
  let header;
  try {
    header = JSON.parse(Buffer.from(tokenParts[0], 'base64').toString())
  } catch (exception) {
    return callback(false, {msg: exception.message})
  }
  if (header.alg != 'RS256')
    return callback(false, {msg: 'token alg must be RS256', found: header.alg})
  let claims;
  try {
    claims = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString())
  } catch (exception) {
    return callback(false, {msg: exception.message})
  }
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
            let missingScopes = scopes.filter(sc => !claims.scope.includes(sc))
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

let PUBLIC_KEYS = {
}

let ISSUER_DISCOVER_DOCS = {
}

function getDiscoveryDocument(errorHandler, issuer, callback) {
  let discoveryUrl = url.resolve(issuer, '/.well-known/openid-configuration')
  withExternalResourceDo(errorHandler, discoveryUrl, {accept: 'application/json'}, callback)
}

function withIssuerTokenKeyURL(errorHandler, issuer, callback) {
  if (issuer in ISSUER_DISCOVER_DOCS)
    callback(ISSUER_DISCOVER_DOCS[issuer].jwks_uri)
  else
    getDiscoveryDocument(errorHandler, issuer, (jso) => {
      ISSUER_DISCOVER_DOCS[issuer] = jso
      callback(jso.jwks_uri)
    })
}

function getPublicKeyForIssuer(errorHandler, issuer, callback) {
  withIssuerTokenKeyURL(errorHandler, issuer, (issuerTokenKeyURL) => {
    withExternalResourceDo(errorHandler, issuerTokenKeyURL, {accept: 'application/json'}, (jso) => {
      let keys
      let key = jso.value
      if (issuer in PUBLIC_KEYS) {
        keys = PUBLIC_KEYS[issuer]
        if (keys.length == 2)
          keys.pop()
        keys.unshift(key)
      } else
        keys = PUBLIC_KEYS[issuer] = [key]
      callback(keys)
    })
  })
}

function withPublicKeysForIssuerDo(errorHandler, issuer, callback) {
  if (issuer in PUBLIC_KEYS)
    callback(PUBLIC_KEYS[issuer])
  else
    getPublicKeyForIssuer(errorHandler, issuer, callback)
}

function refreshPublicKeysForIssuers() {
  log('http-helper-functions:refreshPublicKeysForIssuers', `refreshing token for ${Object.keys(PUBLIC_KEYS)}`)
  let res = errorHandler(err => log('http-helper-functions:refreshPublicKeysForIssuers', `statusCode: ${err.statusCode} body: ${err.body}`))
  for (let issuer in PUBLIC_KEYS) {
    getPublicKeyForIssuer(res, issuer, (keys) => {})
  }
}

let refreshPublicKeysForIssuersTimer = setInterval(refreshPublicKeysForIssuers, TOKEN_KEY_REFERESH_INTERVAL)
function finalize() {
  refreshPublicKeysForIssuersTimer.unref()
}

function isValidTokenFromIssuer(token, res, scopes, allowedIssuers, callback) {
  if (token) {
    let claims = getClaimsFromToken(token)

    if (!claims) {
        callback(false, {msg: `invalid bearer token`});
        return;
    }

    let issuer = claims.iss
    if (allowedIssuers && Array.isArray(allowedIssuers) && !allowedIssuers.includes(issuer))
      callback(false, {msg: `issuer ${issuer} not authorized`})
    else
      withPublicKeysForIssuerDo(res, issuer, (keys) => {
        isValidToken(token, keys, scopes, callback)
    })
  }
  else
    callback(false, {msg: 'no token provided'})
}

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
  sendRequestThen(errorHandler, 'POST', tokenURL, headers, body, function(clientRes) {
    getClientResponseBody(clientRes, function(resp_body) {
      if (clientRes.statusCode == 200) {
        let accessToken = JSON.parse(resp_body).access_token
        let refreshToken = JSON.parse(resp_body).refresh_token
        log('getTokensFromCodeThen', `retrieved token for: ${clientID}`)
        callback(accessToken, refreshToken)
      } else {
        log('getTokensFromCodeThen', `unable to retrieve token. tokenURL: ${tokenURL}, headers: ${util.inspect(headers)} body: ${body}`)
        badRequest(null, errorHandler, {msg: 'unable to retrieve client token', body: resp_body})
      }
    })
  })
}

//
function refreshTokenFromIssuer(res, refreshToken, clientID, clientSecret, tokenURL, callback) {
  var headers = {'content-type': 'application/x-www-form-urlencoded;charset=utf-8', accept: 'application/json;charset=utf-8'}
  var body = `grant_type=refresh_token&client_id=${encodeURIComponent(clientID)}&client_secret=${encodeURIComponent(clientSecret)}&refresh_token=${refreshToken}`
  sendRequestThen(res, 'POST', tokenURL, headers, body, function(clientRes) {
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
            forbidden(req, res, {msg: 'invalid xsrf token'})
          }
        } else {
          forbidden(req, res, {msg: 'xsrf token expired'})
        }
      } else {
        forbidden(req, res, {msg: 'invalid xsrf token'})
      }
    } else {
      forbidden(req, res, {msg: 'missing xsrf token'})
    }
  }
}

function validateTokenThen(req, res, scopes, allowedIssuers, callback) {
  if (CHECK_IDENTITY) {
    let token = getTokenFromReq(req)
    isValidTokenFromIssuer(token, res, scopes, allowedIssuers, (isValid, reason) => {
      if (isValid) {
        // valid token in the authorization header.
        // if this is a modification request on the host for browsers
        // then the xsrf token must be present and correct
        ifXsrfHeaderValidThen(req, res, () => {
          // If there is an x-client-authorization token it has to be good too
          let clientToken = getToken(req.headers['x-client-authorization'])
          if (clientToken)
            isValidTokenFromIssuer(clientToken, res, scopes, allowedIssuers, (isValid, reason) => {
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
            isValidTokenFromIssuer(clientToken, res, scopes, allowedIssuers, (isValid, reason) => {
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
  } else
    if (req.headers.authorization)
      callback(true)
    else
      callback(false, {msg: 'no token provided'})

  function validate_html_get() {
    getSSOCookies(req, (accessToken, refreshToken) => {
      isValidTokenFromIssuer(accessToken, res, scopes, allowedIssuers, (isValid, reason) => {
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
                isValidTokenFromIssuer(accessToken, res, scopes, allowedIssuers, (isValid, reason) => {
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
      user: getUserFromReq(req),
      'request-id': req.headers['x-request-id']
    }
  return context
}

function forEachDoAsyncByChunkThen(elements, itemCallback, finalCallback, chunkSize=10) {
  let totalCount = elements.length
  if (totalCount == 0)
    finalCallback()
  else
    doChunkThen(0)
  
  function doChunkThen(chunk) {
    let limit = Math.min(totalCount, (chunk + 1) * chunkSize)
    let start = chunk * chunkSize
    let todoCount = limit - start
    for (let i = start; i < limit; i++)
      itemCallback(doneOne, elements[i], i, chunk)
    function doneOne() {
      if (--todoCount == 0)
        if (limit < totalCount)
          doChunkThen(chunk + 1)
        else
          finalCallback()
    }
  }
}

function forEachDoAsyncThen(elements, itemCallback, finalCallback, limit = Infinity) {
  let totalCount = elements.length
  let todoCount = totalCount
  limit = Math.min(limit, totalCount)
  let issuedCount = limit
  if (totalCount == 0)
    return finalCallback()
  else
    for (let i = 0; i < limit; i++)
      itemCallback(doneOne, elements[i], i)
  function doneOne() {
    if (--todoCount == 0)
      finalCallback()
    else
      if (issuedCount < totalCount)
        itemCallback(doneOne, elements[issuedCount], issuedCount++)
  }
}

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
exports.ok = found
exports.created = created
exports.respond = respond
exports.internalizeURL = internalizeURL
exports.internalizeURLs = internalizeURLs
exports.getUser = getUser
exports.getUserFromReq = getUserFromReq
exports.getScopes = getScopes
exports.getToken = getToken
exports.getTokenFromReq = getTokenFromReq
exports.forbidden = forbidden
exports.unauthorized = unauthorized
exports.applyPatch = applyPatch
exports.internalError = internalError
exports.setStandardCreationProperties = setStandardCreationProperties
exports.setStandardModificationProperties = setStandardModificationProperties
exports.getUserFromToken = getUserFromToken
// Kept for backwards compatibility
exports.sendInternalRequestThen=sendInternalRequestThen
// Kept for backwards compatibility
exports.sendInternalRequest=sendInternalRequest
exports.sendRequestThen=sendRequestThen
exports.sendRequest=sendRequest
exports.withResourceDo = withInternalResourceDo
exports.patchResourceThen = patchInternalResourceThen
exports.postToResourceThen = postToInternalResourceThen
exports.deleteResourceThen = deleteResourceThen
exports.toHTML=toHTML
exports.uuid4 = uuid4
// Kept for backwards compatibility
exports.sendExternalRequest = sendExternalRequest
// Kept for backwards compatibility
exports.sendExternalRequestThen = sendExternalRequestThen
exports.flowThroughHeaders = flowThroughHeaders
 // Kept for backwards compatibility
exports.withInternalResourceDo = withInternalResourceDo
// Kept for backwards compatibility
exports.patchInternalResourceThen = patchInternalResourceThen
// Kept for backwards compatibility
exports.postToInternalResourceThen = postToInternalResourceThen
// Kept for backwards compatibility
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
exports.finalize=finalize
exports.forEachDoAsyncByChunkThen = forEachDoAsyncByChunkThen
exports.forEachDoAsyncThen = forEachDoAsyncThen
exports.preconditionFailed = preconditionFailed
exports.uuidw = uuidw
exports.errorHandler = errorHandler

// exported for testing only
exports.isValidTokenFromIssuer = isValidTokenFromIssuer
