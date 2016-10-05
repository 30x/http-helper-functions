'use strict';
const http = require('http')
const jsonpatch= require('jsonpatch')
const randomBytes = require('crypto').randomBytes

var INTERNAL_SCHEME = process.env.INTERNAL_SCHEME || 'http';
var INTERNALURLPREFIX = 'protocol://authority';
var INTERNAL_ROUTER = process.env.INTERNAL_ROUTER;
var SHIPYARD_PRIVATE_SECRET = process.env.SHIPYARD_PRIVATE_SECRET
if (SHIPYARD_PRIVATE_SECRET !== undefined) {
  SHIPYARD_PRIVATE_SECRET = new Buffer(SHIPYARD_PRIVATE_SECRET).toString('base64');
}

function sendInternalRequest(serverReq, res, pathRelativeURL, method, body, headers, callback) {
  if (typeof headers == 'function') {
    callback = headers
    headers = {}
  }
  var keys = Object.keys(headers).map(x=>x.toLowerCase())
  if (keys.indexOf('accept') == -1)
    headers['accept'] = 'application/json'
  if (keys.indexOf('host') == -1)
    headers['host'] = serverReq.headers.host
  if (body) {
    if (keys.indexOf('content-type') == -1)
      headers['content-type'] = 'application/json'
    headers['content-length'] = Buffer.byteLength(body)
  }
  if (serverReq.headers.authorization !== undefined)
    headers.authorization = serverReq.headers.authorization; 
  if (SHIPYARD_PRIVATE_SECRET !== undefined)
    headers['x-routing-api-key'] = SHIPYARD_PRIVATE_SECRET
  var hostParts = INTERNAL_ROUTER.split(':')
  var options = {
    protocol: `${INTERNAL_SCHEME}:`,
    hostname: hostParts[0],
    path: pathRelativeURL,
    method: method,
    headers: headers
  }
  if (hostParts.length > 1)
    options.port = hostParts[1]
  var clientReq = http.request(options, callback)
  clientReq.on('error', function (err) {
    console.log(`sendInternalRequest: error ${err}`)
    internalError(res, err)
  });
  if (body) clientReq.write(body)
  clientReq.end();
}

function getServerPostObject(req, res, callback) {
  var body = '';
  req.on('data', function (data) {
    if (body.length + data.length > 1e6){
      req.connection.destroy();
    }
    body += data;
  });
  req.on('end', function () {
    var contentType = req.headers['content-type']
    if (contentType === undefined || (contentType.lastIndexOf('application/', 0) > -1 && contentType.lastIndexOf('json') == contentType.length-4)) {
      var jso;
      try {
        jso = JSON.parse(body);
      }
      catch (err) {
        badRequest('invalid JSON: ' + err.message)
      }
      if (jso)
        callback(req, res, jso)
    } else
      badRequest(res, 'input must be JSON')
  });
}

function getServerPostBuffer(req, res, callback) {
  var body = [];
  req.on('data', function (data) {
    if (body.length + data.length > 1e6){
      req.connection.destroy();
    }
    body.push(data);
  });
  req.on('end', function () {
    callback(req, res, Buffer.concat(body));
  });
}

function getClientResponseBody(res, callback) {
  res.setEncoding('utf8');
  var body = '';
  res.on('data', (chunk) => {
    body += chunk;
  });
  res.on('end', () => {
    callback(body);
  });
}

function getUserFromToken(token) {
  var claims64 = token.split('.');
  if (claims64.length != 3) {
    return null;
  } else {
    var claimsString = new Buffer(claims64[1], 'base64').toString();
    var claims = JSON.parse(claimsString);
    return `${claims.iss}#${claims.sub}`;
  }
}

function getUser(req) {
  var auth = req.headers.authorization;
  if (auth == undefined) {
    return null;
  } else {
    var auth_parts = auth.match(/\S+/g);
    if (auth_parts.length < 2 || auth_parts[0].toLowerCase() != 'bearer') {
      return null;
    } else {
      return getUserFromToken(auth_parts[1]);
    }
  }
}

function methodNotAllowed(req, res, allow) {
  var body = 'Method not allowed. request-target: ' + req.url + ' method: ' + req.method + '\n';
  body = JSON.stringify(body);
  res.writeHead(405, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body),
                      'Allow': allow.join(', ') });
  res.end(body);
}

function notFound(req, res) {
  var body = `Not Found. component: ${process.env.COMPONENT} request-target: //${req.headers.host}${req.url} method: ${req.method}\n`;
  body = JSON.stringify(body);
  res.writeHead(404, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)});
  res.end(body);
}

function forbidden(req, res) {
  var body = `Forbidden. component: ${process.env.COMPONENT} request-target: //${req.headers.host}${req.url} method: ${req.method} user: ${getUser(req)}\n`;
  body = JSON.stringify(body);
  res.writeHead(403, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)});
  res.end(body);
}

function unauthorized(req, res) {
  var body = 'Unauthorized. request-target: ' + req.url;
  body = JSON.stringify(body);
  res.writeHead(401, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)});
  res.end(body);
}

function badRequest(res, err) {
  var body = JSON.stringify(err);
  res.writeHead(400, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)});
  res.end(body);
}   

function internalError(res, err) {
  var body = JSON.stringify(err);
  res.writeHead(500, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)});
  res.end(body);
}   

function duplicate(res, err) {
  var body = JSON.stringify(err);
  res.writeHead(409, {'Content-Type': 'application/json',
                      'Content-Length': Buffer.byteLength(body)});
  res.end(body);
}   

function found(req, res, body, etag, location, contentType) {
  var headers = {};
  if (location !== undefined) {
    headers['Content-Location'] = location;
  } else {
    headers['Content-Location'] = '//' + req.headers.host + req.url; //todo - handle case where req.url includes http://authority
  }
  if (etag !== undefined) {
    headers['Etag'] = etag;
  } 
  respond(req, res, 200, headers, body, contentType);
}

function created(req, res, body, location, etag, contentType) {
  var headers =  {};
  if (location !== undefined) {
    headers['Location'] = location;
  } 
  if (etag !== undefined) {
    headers['Etag'] = etag; 
  }
  respond(req, res, 201, headers, body, contentType);
}

function respond(req, res, status, headers, body, contentType) {
  if (body !== undefined) {
    // If contentType is provided, body is assumed to be the representation of the resource, ready to be sent in the response. If
    // contentType is not provided, the body is assumed to be the state of the resource in Javascript objects. As such, it is
    // subject to content negotiation of the response format.
    var wantsHTML = req.headers.accept !== undefined && req.headers.accept.lastIndexOf('text/html', 0) > -1;
    headers['Content-Type'] = contentType ? contentType : wantsHTML ? 'text/html' : 'application/json'
    if (!('Content-Type' in headers)) {
      headers['Content-Type'] = 'application/json';
    }
    externalizeURLs(body, req.headers.host);
    var contentType = headers['Content-Type']
    body = body instanceof Buffer ? body : contentType == 'text/html' ? toHTML(body) : contentType == 'text/plain' ? body.toString() : contentType == 'application/json' ? JSON.stringify(body) : body.toString();
    headers['Content-Length'] = Buffer.byteLength(body);
    res.writeHead(status, headers);
    res.end(body);
  } else { 
    res.writeHead(status, headers);
    res.end();
  }
}

function internalizeURL(anURL, authority) {
  var httpString = 'http://' + authority;
  var httpsString = 'https://' + authority;  
  var schemelessString = '//' + authority;  
  anURL = decodeURIComponent(anURL);
  if (anURL.lastIndexOf(httpString, 0) === 0) {
    return INTERNALURLPREFIX + anURL.substring(httpString.length);
  } else if (anURL.lastIndexOf(httpsString, 0) === 0) {
    return INTERNALURLPREFIX + anURL.substring(httpsString.length);
  } else if (anURL.lastIndexOf(schemelessString, 0) === 0) {
    return INTERNALURLPREFIX + anURL.substring(schemelessString.length);
  } else if (anURL.lastIndexOf('/', 0) === 0) {
    return INTERNALURLPREFIX + anURL;
  } else {
    return anURL;
  }
}

function internalizeURLs(jsObject, authority) {
  //strip the http://authority or https://authority from the front of any urls
  if (Array.isArray(jsObject)) {
    for (var i = 0; i < jsObject.length; i++) {
      jsObject[i] = internalizeURLs(jsObject[i], authority);
    }             
  } else if (typeof jsObject == 'object') {
    for(var key in jsObject) {
      if (jsObject.hasOwnProperty(key)) {
        jsObject[key] = internalizeURLs(jsObject[key], authority);
      }
    }
  } else if (typeof jsObject == 'string') {
    return internalizeURL(jsObject, authority)
  }
  return jsObject;
}

function externalizeURLs(jsObject, authority) {
  //add http://authority or https://authority to the front of any urls
  if (Array.isArray(jsObject)) {
    for (var i = 0; i < jsObject.length; i++) {
      jsObject[i] = externalizeURLs(jsObject[i], authority);
    }
  } else if (typeof jsObject == 'object') {
    for(var key in jsObject) {
      if (jsObject.hasOwnProperty(key)) {
        jsObject[key] = externalizeURLs(jsObject[key], authority);
      }
    }
  } else if (typeof jsObject == 'string') {
    if (jsObject.lastIndexOf(INTERNALURLPREFIX, 0) === 0) {
      var prefix = `//${authority}`;
      return prefix + jsObject.substring(INTERNALURLPREFIX.length);
    }
  }             
  return jsObject
}  

// move somewhere else?
function createPermissonsFor(serverReq, serverRes, resourceURL, permissions, callback) {
  var user = getUser(serverReq);
  if (user == null) {
    unauthorized(serverReq, serverRes);
  } else {
    if (permissions === null || permissions === undefined) {
      permissions = {
        _subject: resourceURL,
        _permissions: {
          read: [user],
          update: [user],
          delete: [user]
        },
        _self: {
          read: [user],
          delete: [user],
          update: [user],
          create: [user]
        }
      }
    } else {
      if (permissions._self === undefined) {
        permissions._self = {}
      }
      if (permissions._subject === undefined) {
        permissions._subject = resourceURL
      } else {
        if (permissions._subject != resourceURL) {
          badRequest(serverRes, 'value of _subject must match resourceURL');
        }
      }
      var permissionsPermissons = permissions._permissions;
      if (permissionsPermissons === undefined) {
        permissions._permissions = permissionsPermissons = {};
      }
      if (permissions._inheritsPermissionsOf === undefined && permissionsPermissons.update === undefined) {
        permissionsPermissons.update = [user];
        permissionsPermissons.read = permissions.read || [user];
      } 
    }
    var postData = JSON.stringify(permissions);
    sendInternalRequest(serverReq, serverRes, '/permissions', 'POST', postData, function (clientRes) {
      getClientResponseBody(clientRes, function(body) {
        if (clientRes.statusCode == 201) { 
          body = JSON.parse(body);
          internalizeURLs(body, serverReq.headers.host);
          callback(resourceURL, body);
        } else if (clientRes.statusCode == 400) {
          badRequest(serverRes, body);
        } else if (clientRes.statusCode == 403) {
          forbidden(serverReq, serverRes);
        } else {
          var err = {statusCode: clientRes.statusCode,
            msg: `failed to create permissions for ${resourceURL} statusCode ${clientRes.statusCode} message ${body}`
          }
          internalError(serverRes, err);
        }
      });
    });
  }
}

// move somewhere else?
function withAllowedDo(req, serverRes, resourceURL, property, action, callback) {
  var user = getUser(req);
  var resourceURLs = Array.isArray(resourceURL) ? resourceURL : [resourceURL];
  var qs = resourceURLs.map(x => `resource=${x}`).join('&');
  var permissionsURL = `/is-allowed?${qs}`;
  if (user !== null) {
    permissionsURL += '&user=' + user.replace('#', '%23');
  }
  if (action !== null) {
    permissionsURL += '&action=' + action;
  }
  if (property !== null) {
    permissionsURL += '&property=' + property;
  }
  sendInternalRequest(req, serverRes, permissionsURL, 'GET', undefined, function (clientRes) {
    getClientResponseBody(clientRes, function(body) {
      try {
        body = JSON.parse(body);
      } catch (e) {
        console.error('withAllowedDo: JSON parse failed. url:', permissionsURL, 'body:', body, 'error:', e);
      }
      if (clientRes.statusCode == 200) { 
        callback(body);
      } else {
        internalError(serverRes, `failed permissions request: statusCode: ${clientRes.statusCode} URL: ${permissionsURL} body: ${JSON.stringify(body)}`);
      }
    });
  });
}

// move somewhere else?
function ifAllowedThen(req, res, resourceURL, property, action, callback) {
  resourceURL =  resourceURL || '//' + req.headers.host + req.url
  withAllowedDo(req, res, resourceURL, property, action, function(allowed) {
    if (allowed === true) {
      callback();
    } else {
      if (getUser(req) !== null) {
        forbidden(req, res);
      } else { 
        unauthorized(req, res);
      }
    }
  });
}

function mergePatch(target, patch) {
  if (typeof patch == 'object' && !Array.isArray(patch)) {
    if (typeof target != 'object') {
      target = {}; // don't just return patch since it may have nulls; perform the merge
    } else {
      target = Object.assign({}, target);
    }
    for (var name in patch) {
      if (patch.hasOwnProperty(name)) {
        var value = patch[name];
        if (value === null) {
          if (name in target) {
            delete target[name];
          }
        } else {
           target[name] = mergePatch(target[name], value);
        }
      }
    }
    return target;
  } else {
    return patch;
  }
}

function applyPatch(req, res, target, patch, callback) {
  if ('content-type' in req.headers) {
    if (req.headers['content-type'] == 'application/merge-patch+json')
      callback(mergePatch(target, patch))
    else if (req.headers['content-type'] == 'application/json-patch+json')
      callback(jsonpatch.apply_patch(target, patch))
    else
      badRequest(res, `unknown PATCH content-type: ${req.headers['content-type']}`)  
  } else 
    badRequest(res, 'PATCH headers missing content-type for patch')
}

function setStandardCreationProperties(req, resource, user) {
  if (resource.creator) {
    return 'may not set creator'
  } else {
    resource.creator = user
  }
  if (resource.modifier) {
    return 'may not set modifier'
  } else {
    resource.modifier = user
  }
  if (resource.created) {
    return 'may not set created'
  } else {
    resource.created = new Date().toISOString()
  }
  if (resource.modified) {
    return 'may not set modified'
  } else {
    resource.modified = resource.created
  }
  return null;
}

function toHTML(body) {
  const increment = 25;
  function valueToHTML(value, indent, name) {
    if (typeof value == 'string') {
      if (value.lastIndexOf('http', 0) > -1 || value.lastIndexOf('./', 0) > -1 || value.lastIndexOf('/', 0) > -1) {
        return `<a href="${value}"${name === undefined ? '': ` property="${name}"`}>${value}</a>`;
      } else {
        return `<span${name === undefined ? '': ` property="${name}"`} datatype="string">${value}</span>`;
      }  
    } else if (typeof value == 'number') {
      return `<span${name === undefined ? '': ` property="${name}"`} datatype="number">${value.toString()}</span>`;
    } else if (typeof value == 'boolean') {
      return `<span${name === undefined ? '': ` property="${name}"`} datatype="boolean">${value.toString()}</span>`;
    } else if (Array.isArray(value)) {
      var rslt = value.map(x => `<li>${valueToHTML(x, indent)}</li>`);
      return `<ol${name === undefined ? '': ` property="${name}"`}>${rslt.join('')}</ol>`;
    } else if (typeof value == 'object') {
      var rslt = Object.keys(value).map(name => propToHTML(name, value[name], indent+increment));
      return `<div${value.self === undefined ? '' : ` resource=${value.self}`} style="padding-left:${indent+increment}px">${rslt.join('')}</div>`;
    }
  }
  function propToHTML(name, value, indent) {
    return `<p>${name}: ${valueToHTML(value, indent, name)}</p>`;
  }
  return `<!DOCTYPE html><html><head></head><body>${valueToHTML(body, -increment)}</body></html>`;
} 

// The following function contains some code copied from https://github.com/broofa/node-uuid4 under MIT License
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

exports.getServerPostObject = getServerPostObject
exports.getServerPostBuffer = getServerPostBuffer
exports.getClientResponseBody = getClientResponseBody
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
exports.forbidden = forbidden
exports.unauthorized = unauthorized
exports.ifAllowedThen = ifAllowedThen
exports.withAllowedDo = withAllowedDo
exports.applyPatch = applyPatch
exports.internalError = internalError
exports.createPermissonsFor = createPermissonsFor
exports.setStandardCreationProperties = setStandardCreationProperties
exports.getUserFromToken = getUserFromToken
exports.sendInternalRequest=sendInternalRequest
exports.toHTML=toHTML
exports.uuid4 = uuid4