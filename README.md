PHP-Lite-ContextIO
==================

The PHP client library for the Lite Context.IO API

This repository contains the PHP Client Library for Context.IO. Please consult
http://context.io for more information regarding Context.IO.


REQUIREMENTS

PHP Curl (http://php.net/curl)


INSTALLATION

Copy class.contextio.php, class.contextioresponse.php and OAuth.php into the
same directory.

You only need to include class.contextio.php in your code, other libraries are
included by class.contextio.php.


EXAMPLES

```php
// include the lib
include_once("class.contextio.php");

// define your API key and secret - find this https://console.context.io/#settings
define('CONSUMER_KEY', 'YOUR API CONSUMER KEY');
define('CONSUMER_SECRET', 'YOUR API CONSUMER SECRET');

// instantiate the contextio object
$contextio = new ContextIO(CONSUMER_KEY, CONSUMER_SECRET);

// get a list of users and print the response data out
$r = $contextio->listUsers();
print_r($r->getData());

// many calls are based for a User - you can define a USER_ID to make these calls
// the USER_ID is returned in either the listUsers call or the getUser call
// you can also get this from the interactive console
define('USER_ID', 'A CONTEXTIO USER ID');

// You also need to know the EMAIL_ACCOUNT_LABEL and FOLDER to list messages.
$r = $contextio->listEmailAccounts(USER_ID);
print_r($r->getData());

// You can see all the folders in an email account using the listEmailAccountFolders method
define('LABEL', 'AN EMAIL ACCOUNT LABEL');
$params = array('label'=>LABEL);
$r = $contextio->listEmailAccountFolders(USER_ID, $params);
print_r($r);

// Now that you know the USER_ID, LABEL, and FOLDER you can list messages
define('FOLDER', 'A FOLDER NAME')
$params = array('label'=>LABEL, 'folder'=>FOLDER);
$r = $contextio->listMessages(USER_ID, $params);
print_r($r);
```

Refer to the class.contextio.php file to see a list of all the methods.
