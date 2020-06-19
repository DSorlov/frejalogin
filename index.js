const express       = require('express');
const session       = require('express-session')
const bodyParser    = require('body-parser');
const fs            = require('fs');
const ejs           = require('ejs');
const path          = require('path');
const http          = require('http');
const https         = require('https');
const xpath         = require('xpath');
const xmldom        = require('xmldom');
const SignedXml     = require('xml-crypto').SignedXml;
const saml20        = require('saml').Saml20;
const uuid          = require('uuid');
const helmet        = require('helmet');


// Get our config!
const version = process.env.npm_package_version ? process.env.npm_package_version : JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'))).version;
const config = JSON.parse(fs.readFileSync(path.join(__dirname, './data', 'config.json')));

// Setup servers
var privateKey = fs.readFileSync(path.join(__dirname, config.service.key_file));
var certificate = fs.readFileSync(path.join(__dirname, config.service.cert_file));
var credentials = {key: privateKey, cert: certificate};
var app = express();
var httpsServer = https.createServer(credentials, app);
var io = require("socket.io")(httpsServer);

// Sessions
var io_session = require("express-socket.io-session");
var e_session = require("express-session");
var ee_session = e_session({
    secret: config.service.cookie_secret,
    resave: true,
    saveUninitialized: true,
    cookie: { secure: true },
    name: 'sessionid'
});
var sharedsession = require("express-socket.io-session");
const { Console } = require('console');
io.use(io_session(ee_session, { autoSave:true })); 

// Default claims provided by our solitons
var outboundClaims=[];
outboundClaims.push({id: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant', name: 'Authentication Instant'});
outboundClaims.push({id: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod', name: 'Authentication Method'});
outboundClaims.push({id: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/authenticated', name: 'User Authentication State'});
outboundClaims.push({id: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', name: 'E-mail Address'});
outboundClaims.push({id: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier', name: 'Name ID'});
outboundClaims.push({id: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', name: 'Name'});
outboundClaims.push({id: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', name: 'Given Name'});
outboundClaims.push({id: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname', name: 'Surname'});

// Fetch all templates from the disk and enter them into the array
var templates = {};
fs.readdirSync(path.join(__dirname, './templates')).forEach(function (tmplFile) {
  var content = fs.readFileSync(path.join(__dirname, './templates', tmplFile));
  var template = ejs.compile(content.toString());
  templates[tmplFile.slice(0, -4)] = template;
});

// Supporting function to compare bolleanish strings
function strbool(value) {
  return value=="true" ? true : false;
}

// Read a certificate file, strip it from junk and remove all line endings.
function getCertificate(certfile) {
    var cert = fs.readFileSync(path.join(__dirname, certfile))
    var pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
    if (pem && pem.length > 0) {
      return pem[2].replace(/[\n|\r\n]/g, '');
    }
    return null;
};

// Resolve the hostname for this host
function getHost(req, endpointPath) { 
    var protocol = req.headers['x-forwarded-proto'] || req.protocol;
    var host = req.headers['x-forwarded-host'] || req.headers['host'];
    return protocol + '://' + host + endpointPath;
}

// Create a time to use in SAML responses
function getInstant(date) {
  return date.getUTCFullYear() + '-' +
    ('0' + (date.getUTCMonth() + 1)).slice(-2) + '-' +
    ('0' + date.getUTCDate()).slice(-2) + 'T' +
    ('0' + date.getUTCHours()).slice(-2) + ":" +
    ('0' + date.getUTCMinutes()).slice(-2) + ":" +
    ('0' + date.getUTCSeconds()).slice(-2) + "." +
    ('00' + date.getUTCMilliseconds()).slice(-3) + "Z";
};

// Create a saml and sign it
function buildSamlResponse(options) {
  var SAMLResponse = templates.samlresponse({
    id:             '_' + uuid.v4(),
    instant:        getInstant(new Date()),
    destination:    options.destination || options.audience,
    inResponseTo:   options.inResponseTo,
    issuer:         options.issuer,
    samlStatusCode: options.samlStatusCode,
    samlStatusMessage: options.samlStatusMessage,
    assertion:      options.signedAssertion || ''
  });

  var cannonicalized = SAMLResponse.replace(/\r\n/g, '').replace(/\n/g,'').replace(/>(\s*)</g, '><').trim();
  var sig = new SignedXml(null, { signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' });
  sig.addReference("//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],"http://www.w3.org/2001/04/xmlenc#sha256");
  sig.signingKey = options.key;

  sig.keyInfoProvider = {
    getKeyInfo: function (key, prefix) {
      prefix = prefix ? prefix + ':' : prefix;
      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + options.cert + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
    }
  };

  sig.computeSignature(cannonicalized, { prefix: options.signatureNamespacePrefix, location: { action: 'after', reference: "//*[local-name(.)='Issuer']" }});
  return sig.getSignedXml();
}



// ***************************************************************************************
// MAIN APPLICATION CODE
// ***************************************************************************************

if (process.argv && process.argv[2] && process.argv[2]==='-generate') {
  console.log("Generating files..")
  for(var idp in config) {
    if (idp!="service") {
      var signingCert = getCertificate(config[idp].issuer.cert_file);
      var idpXml = templates.metadata({
        signingPem:        signingCert,
        redirectEndpoint:  "https://"+config.service.hostname+":"+config.service.port+"/"+idp+"/login",
        postEndpoint:      "https://"+config.service.hostname+":"+config.service.port+"/"+idp+"/login",
        claimTypes:        outboundClaims,
        issuer:            config[idp].issuer.name,
        issuerContact:     config[idp].issuer.contact,
        issuerEmail:       config[idp].issuer.email,
        issuerDisplayName: config[idp].issuer.display_name,
        issuerUrl:         config[idp].issuer.url,
      })
      fs.writeFileSync(path.join(__dirname,`./data/metadata/${config[idp].domain.replace(".","_")}.xml`), idpXml, (err)=>{
      });
      console.log("Created static Metadata for "+config[idp].domain.replace(".","_")+" in /data/metadata")
      var idpPS = templates.powershell({
        domainName: config[idp].domain,
        serviceHost: config.service.hostname,
        servicePort: config.service.port,
        idp: idp,
        signingCert: signingCert
      });
      fs.writeFileSync(path.join(__dirname,`./data/powershell/${config[idp].domain.replace(".","_")}.ps1`), idpPS, (err)=>{
      });
      console.log("Created PowerShell configuration for "+config[idp].domain.replace(".","_")+" in /data/powershell")
    }
  }
  process.exit();
}

// Start the basic server to handle incomming requests
app.set('trust proxy', 1) // trust first proxy
app.use(ee_session);
app.use(helmet());
app.use(bodyParser.urlencoded({extended: true}));
app.use("/resources/", express.static(path.join(__dirname, './resources')));

// Expose the metadata endpoint
app.get('/:site/FederationMetadata/2007-06/FederationMetadata.xml', (req, res) => {
  var site = req.params.site;

  if (!config[site]) {
    return res.status(404).send(templates.error_404({
      moduleversion: version,
      nodeversion: process.version
    }));  
  }

  res.set('Content-Type', 'application/xml');
  res.send(templates.metadata({
    signingPem:        getCertificate(config[site].issuer.cert_file),
    redirectEndpoint:  "https://"+config.service.hostname+":"+config.service.port+"/"+idp+"/login",
    postEndpoint:      "https://"+config.service.hostname+":"+config.service.port+"/"+idp+"/login",
    claimTypes:        outboundClaims,
    issuer:            config[site].issuer.name,
    issuerContact:     config[site].issuer.contact,
    issuerEmail:       config[site].issuer.email,
    issuerDisplayName: config[site].issuer.display_name,
    issuerUrl:         config[site].issuer.url,
  }).replace(/\n(?:\s*\n)+/g, '\n'));
});

// Show the login form
app.post("/:site/login", (req, res) => {
  var site = req.params.site;

  if (!config[site]) {
    return res.status(404).send(templates.error_404({
      moduleversion: version,
      nodeversion: process.version
    }));  
  }
  
  var samlRequestDom = new xmldom.DOMParser().parseFromString(Buffer.from(req.body.SAMLRequest, 'base64').toString('utf-8'));
  var relayState = req.body.RelayState;
  var request_user = req.body.username;
  var request_issuer = xpath.select("//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()",samlRequestDom);
  resuest_issuer = (request_issuer && request_issuer.length > 0) ? request_issuer[0].textContent: "";
  var request_id = samlRequestDom.documentElement.getAttribute('ID');

  req.session.relayState = relayState;
  req.session.requestUser = request_user;
  req.session.requestId = request_id;
  req.session.service = site;
  req.session.save();

  res.send(templates[`loginform_${config[site].template}`]({
    userId: request_user,
    logoUrl: config[site].logo_url,
    logoText: config[site].display_name,
    helpText: config[site].help_text,
    termsUrl: config[site].terms_url,
    privacyUrl: config[site].privacy_url,
    pageTitle: config[site].title
  }));
});

// Handle 404
app.use(function (req, res, next) {
  res.status(404).send(templates.error_404({
    moduleversion: version,
    nodeversion: process.version
  }));
})

// Handle 500
app.use(function (err, req, res, next) {
  res.status(500).send(templates.error_500({
    moduleversion: version,
    nodeversion: process.version
  }));
})

// Socket listener
io.on("connection", function(socket) {

  socket.on("authRequest", function() {
    
    socket.emit("authResponse", { status: 'preparing' });

    if (socket.handshake.session.service) {

    const site = socket.handshake.session.service;

    const eidprovider   = require('eid-provider')('frejaorgid')
    const eidconfig = eidprovider.settings[config[site].profile];
    for(var override in config[site].settings) {
      if (override==='ca_cert'||override==='jwt_cert'||override==='client_cert'){
        eidconfig[override] = fs.readFileSync(path.join(__dirname, config[site].settings[override]));
      } else {
        eidconfig[override] = config[site].settings[override];
      }
    }
    eidprovider.initialize(eidconfig);
    
    if (config[site].accounting==='true') {
      fs.appendFile(path.join(__dirname,`./data/accunting/${config[site].domain.replace(".","_")}.log`), `${getInstant(new Date())},${socket.handshake.session.requestUser}\r\n`, (err)=>{} );
    }

    eidprovider.authRequest(socket.handshake.session.requestUser, (data)=>{
        socket.emit("authResponse", { status: data.status, code: data.code });
    }, (data)=>{
      socket.emit("authResponse", { status: data.status, code: data.code });
    }).then((data)=>{
      if (data.status='completed') {

        var options = {
          signatureAlgorithm:       'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          digestAlgorithm:          'http://www.w3.org/2001/04/xmlenc#sha256',
          cert:                     getCertificate(config[site].issuer.cert_file),
          key:                      fs.readFileSync(path.join(__dirname, config[site].issuer.key_file)),
          issuer:                   "https://"+config.service.hostname+':'+config.service.port+'/'+site,
          audiences:                'urn:federation:MicrosoftOnline',
          inResponseTo:             socket.handshake.session.requestId,
          signatureNamespacePrefix: 'ds'
        };

        if (!data.user) {
          options.samlStatusCode = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
          options.samlStatusMessage = data.code;
          var SAMLResponse = buildSamlResponse(options);   
          return socket.emit("authResponse", { status: "error", code: "internal_error", action: 'https://login.microsoftonline.com/login.srf', ticket: Buffer.from(SAMLResponse, 'utf-8').toString('base64'), state: socket.handshake.session.relayState })  
        }

        options.lifetimeInSeconds = 3600;
        options.nameIdentifier = Buffer.from(data.user.id, 'utf-8').toString('base64');
        options.nameIdentifierFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
        options.authnContextClassRef = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
        options.attributes = {
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/authenticated': 'true', 
          'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod': eidconfig.minimumLevel, 
          'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant': getInstant(new Date()),
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': Buffer.from(data.user.id, 'utf-8').toString('base64'), 
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': socket.handshake.session.requestUser, 
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': data.user.fullname, 
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': data.user.firstname, 
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': data.user.lastname 
        };      
      
      
        saml20.create(options, function (err, signedAssertion) {
            if (err) {
              options.samlStatusCode = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
              options.samlStatusMessage = err.toString();
              var SAMLResponse = buildSamlResponse(options);   
              socket.emit("authResponse", { status: "error", code: "internal_error", action: 'https://login.microsoftonline.com/login.srf', ticket: Buffer.from(SAMLResponse, 'utf-8').toString('base64'), state: socket.handshake.session.relayState })
            }
            options.signedAssertion = signedAssertion;
            options.samlStatusCode = "urn:oasis:names:tc:SAML:2.0:status:Success";
            var SAMLResponse = buildSamlResponse(options); 
            socket.emit("authResponse", { status: data.status, code: data.code, action: 'https://login.microsoftonline.com/login.srf', ticket: Buffer.from(SAMLResponse, 'utf-8').toString('base64'), state: socket.handshake.session.relayState })
        });
      } else {
        options.samlStatusCode = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
        options.samlStatusMessage = data.code;
        var SAMLResponse = buildSamlResponse(options);   
        socket.emit("authResponse", { status: "error", code: "internal_error", action: 'https://login.microsoftonline.com/login.srf', ticket: Buffer.from(SAMLResponse, 'utf-8').toString('base64'), state: socket.handshake.session.relayState })
      }
    });

  }

  });

});

// Start the https server
httpsServer.listen(config.service.port, () => {
  console.log('Server running on port '+config.service.port);
});
