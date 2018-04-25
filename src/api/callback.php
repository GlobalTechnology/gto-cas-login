<?php namespace GlobalTechnology\CentralAuthenticationService;
define( 'WP_USE_THEMES', false );
require_once( realpath( $_SERVER['DOCUMENT_ROOT'] . '/wp-load.php' ) );
CASLogin::singleton()->get_cas_client()->forceAuthentication();
?>
<html>
<head>
    <title>CAS Callback Handler</title>
</head>
<body>
</body>
</html>
