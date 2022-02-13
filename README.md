![stability-stable](https://img.shields.io/badge/stability-stable-green.svg)
![version](https://img.shields.io/badge/version-0.0.1-green.svg)
![maintained](https://img.shields.io/maintenance/yes/2022.svg)
[![maintainer](https://img.shields.io/badge/maintainer-daniel%20sörlöv-blue.svg)](https://github.com/DSorlov)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://img.shields.io/github/license/DSorlov/eid-provider)

# frejalogin
A minimalistic SAML2.0 Identity Provider for use with Office 365 and Freja eID all written in Node. The project uses [eid-provider](https://www.npmjs.com/package/eid-provider) to communicate with Freja eID services.

## Solution Overview
This project allows you to securly authenticate users on LOA1-LOA3 level using Freja eID er Freja eID Organisational ID.

It is a minimalistic implementation that works by using a federated domain in Office 365 that directs authentication requests to this IdP.
The request to the IdP from Office 365 is done using email as the lookup key. Office 365 currently reqires the response to
return the Immutable of that user to map the response correctly. This presented an interesting
problem as emails are not supported in Immutables (or rather you cannot have @ in the field). We opted for the solution where the
Immutable now is set to a base64 encoded variant of the emailadress. This works by returning the NameID attribute in the SAMLResponse to
Office 365 as just a base64 encoded version of the email.

> Right now only OrganizationID mode is implemented but soon the lookup can be made in `OrganizationID` mode where the OrgID value is matched, or in `PersonalID` where the email field is matched to the incomming request from Office 365. I recomend to use the `OrganizationID` mode as it gives control of that user and that the user have been vetted and that they do not need to link their work email to their personal identity.

## Appliation Overview
The application runs as a HTTPS-server on the specified port on the machine it is started. It is mostly stateless (unless you enable accounting in which case it logs the requests to the data-directory). The application can support multiple idps (https://server.com/<idpname>/login and https://server.com/<idpname>/FederationMetadata/2007-06/FederationMetadata.xml) for different keys to freja, different signing keys or login page customization).

>/data
In this directory you will find the config.json file containg all the server configuration data. It should be quite obvious what most things do. There are a couple of subdirectories:
- accounting: this is where, if you enable accounting, a file for each IdP is created with every request received
- certs: Suggested place to place any and all certificates and credential files etc
- metadata: If instructed to using the `-generate` commandline switch; it will create static federation metadata files for the endpoint.
- powershell: If instructed to using the `-generate` commandline switch; it will create configuration scripts in powershell for configuring the domains

>/resources
This directory and any subdirectories is served out to the world via https under the /resources url, and contains images, css and more that are used in the templates. Perfect place for logos etc.

>/templates
In this directory you will find the templates used for logins and generating different types of content. Most of the time you will not need to change anything here but you are free to do so. Any changes require the instance to be restarted. Additional layouts for login forms can be created by naming them loginform_<something>.ejs.

>/node_modules
Is created once you have installed the application (as always with node) and is best just ignored.

>/utils
Contains some useful scripts:
- fiximmutable.ps1: Sets the upn and immutable to the email address specified.
- pushorgid.js: Pushes a organization id (email) to a user specified by SSN

## Installation
- Install the application
- Create pem certificate and pem key for signing and put in the certs directory (selfsinged x509 is fine)
- Create pem certificate and pem key for webserver ssl and put in the certs directory (should be a trusted one)
- Update the configuration file, rename the config_sample.json to config.json and start editing
- Optional: Start using `npm start -generate` or `node ./index -generate` to create static files and powershell to configure the domain
- Start using `npm start` or node `./index`
- Run the configuration powershell on your domain
- Optional: Run the pushorgid util to push orgid credentials

## Configuration file
This is a common json file:
```
{
    "service": { // Generic settings for the whole server and IdPs
        "hostname":            Server Name,
        "port":                TCP Port,
        "cookie_secret":       Contains the secret used to secure cookies,
        "cert_file":           The certificate file used for the webserver,
        "key_file":            The certificate key used for the webserver
    },
    "69511aa9-8bf9-472a-a756-b091238a44e4": { // Specific to this IdP
        "domain":              The domain that is federated, or will be, in Office365,
        "profile":             Which Freja backend to use: "production" or "testing",
        "accounting":          Enable accounting: "true",
        "template":            Which loginform_template is used; "microsoft",
        "logo_url":            A logo that is rendered inside the logintemplate,
        "display_name":        This is the display name inside the logintemplate,
        "terms_url":           A terms urls displayed inside the logintemplate,
        "privacy_url":         A privacy url displayed inside the logintemplate,
        "page_title":          The title rendered inside of the logintemplate,
        "help_text":           Text rendered inside the logintemplate,
        "issuer": { // Metadata and issuing for this IdP
            "name":            The issuer name in metadata,
            "display_name":    The display name used in metadata,
            "url":             Your company website used in metadata,
            "contact":         Technical contact name used in the metadata,
            "email":           Technical contact email used in the metadata,    
            "cert_file":       The cert used to sign assertions,
            "key_file":        The key used to sign assertions
        },
        "settings": { // Settings for eid-provider for this IdP
            "client_cert":     The PFX file to use,
            "password":        The password to use,
            "minimum_level":   Minimum level "EXTENDED" or "PLUS" (even "BASIC" works but not recomended)
        }
    }
}
```

