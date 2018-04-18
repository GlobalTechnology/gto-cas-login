<?php namespace GlobalTechnology\CentralAuthenticationService {
    /**
     * CAS Login (Authentication) Plugin
     *
     * Login to WordPress through CAS (Central Authentication Service) using phpCAS.
     * @package    GCX_CAS_Login
     * @subpackage Main
     *
     * @uses       phpCAS 1.3.2
     */

    /**
     * Plugin Name: GTO CAS Login (Authentication)
     * Plugin URI:  https://github.com/GlobalTechnology/gto-cas-login
     * Description: Login to WordPress through CAS (Central Authentication Service) using phpCAS.
     * Author:      Global Technology Office
     * Author URI:  https://github.com/GlobalTechnology
     * Version:     0.1
     * Text Domain: gtocas
     * Domain Path: /languages/
     * License:     Modified BSD
     */

    /*
     * Copyright (c) 2011-2017, CAMPUS CRUSADE FOR CHRIST
     * All rights reserved.
     *
     * Redistribution and use in source and binary forms, with or without modification,
     * are permitted provided that the following conditions are met:
     *
     *     Redistributions of source code must retain the above copyright notice, this
     *      list of conditions and the following disclaimer.
     *     Redistributions in binary form must reproduce the above copyright notice,
     *      this list of conditions and the following disclaimer in the documentation
     *      and/or other materials provided with the distribution.
     *     Neither the name of CAMPUS CRUSADE FOR CHRIST nor the names of its
     *      contributors may be used to endorse or promote products derived from this
     *      software without specific prior written permission.
     *
     * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
     * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
     * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
     * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
     * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
     * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
     * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
     * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
     * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
     * OF THE POSSIBILITY OF SUCH DAMAGE.
     */

    //if phpCAS in not loaded, attempt to include it
    //from the include path, otherwise load the included phpCAS
    if ( ! class_exists( 'CAS_Client', false ) ) {
        require_once dirname(__FILE__).'/../vendor/jasig/phpcas/CAS.php';
//		if( !class_exists( 'CAS_Client' ) )
//			@include_once rtrim( dirname( realpath(__FILE__) ), DIRECTORY_SEPARATOR) . '/lib/phpCAS/source/CAS.php';
    }

    const TEXT_DOMAIN = 'gtocas';

    const VERSION = '0.1';

    class CASLogin {
        /**
         * Singleton instance
         * @var CASLogin
         */
        private static $instance;

        /**
         * Returns the CASLogin singleton
         * @return CASLogin
         */
        public static function singleton() {
            if ( ! isset( self::$instance ) ) {
                $class          = __CLASS__;
                self::$instance = new $class();
            }
            return self::$instance;
        }

        /**
         * Prevent cloning of the object
         */
        private function __clone() {
        }

        /**
         * CAS client mode
         * @var string
         */
        const CLIENT = 'client';

        const USER_META_GUID = 'guid';

        const CAS_ATTRIBUTE_GUID       = 'ssoGuid';
        const CAS_ATTRIBUTE_FIRST_NAME = 'firstName';
        const CAS_ATTRIBUTE_LAST_NAME  = 'lastName';

        public $base_uri;

        /**
         *
         * @var \CAS_Client
         */
        private $_cas_client;

        public $options = array(
            'hostname' => 'thekey.me',
            'port'     => 443,
            'uri'      => 'cas',
        );

        protected function __construct() {
            $this->base_uri = plugin_dir_url( __FILE__ );

            $this->register_actions_filters();
        }

        private function register_actions_filters() {
            //Check here to see if this is a backend page (is_admin), a draft preview ($_GET['preview'])
            //or a Gravity Forms form preview ($_GET['gf_page'] = preview) and only runs these hooks on those pages
            if( is_admin() || isset($_GET['preview']) || (isset($_GET['gf_page']) && $_GET['gf_page'] === 'preview') ) {
                add_action( 'muplugins_loaded', array( &$this, 'initialize_phpcas' ), 5, 0 );

                add_action( 'activate_header', array( &$this, 'user_activate' ), 10, 0 );
                add_action( 'admin_menu', array( &$this, 'remove_add_user_submenu' ), 15 ); //Remove the Add New submenu from the Users menu
                add_filter( 'current_screen', array( &$this, 'redirect_on_add_user_screen' ), 10, 1 );
                add_action( 'admin_menu', function () {
                    add_users_page( __( 'Add Users', TEXT_DOMAIN ), __( 'Add Users', TEXT_DOMAIN ), 'manage_options', 'add-user', array( &$this, 'add_user_page' ) );
                }, 10, 0 );
                add_action( 'admin_init', array( &$this, 'add_users_admin' ), 10, 0 );

                add_filter( 'login_url', array( &$this, 'login_url' ), 0, 1 );
                add_action( 'wp_logout', array( &$this, 'logout' ), 0, 0 );
            }
        }

        final public function initialize_phpcas() {
            $options = (object)$this->options;

            // initialize cookie constants
            if ( is_multisite() )
                ms_cookie_constants();
            wp_cookie_constants();

            $params = session_get_cookie_params();
            session_set_cookie_params( $params[ 'lifetime' ], $params[ 'path' ], $params[ 'domain' ], is_ssl(), $params[ 'httponly' ] );
            session_name( is_ssl() ? SECURE_AUTH_COOKIE : AUTH_COOKIE );

            $this->_cas_client = new \CAS_Client(
                '2.0',
                !!getenv( 'CAS_PROXY_MODE' ),
                getenv( 'CAS_HOSTNAME' ) ? getenv( 'CAS_HOSTNAME' ) : $options->hostname,
                getenv( 'CAS_PORT' ) ? getenv( 'CAS_PORT' ) : $options->port,
                getenv( 'CAS_PATH' ) ? getenv( 'CAS_PATH' ) : $options->uri
            );

            //Attach a callabck for so we know when users are authenticated, this handles new user creation and profile updates
            $this->_cas_client->setPostAuthenticateCallback( array( &$this, 'cas_authenticated' ), array() );

            //Disable SSL server validation.
            //Validation usually fails unless reverse hostname lookup works correctly for the CAS server.
            $this->_cas_client->setNoCasServerValidation();

            //Accept logout requests from CAS, but do not validate the server.
            //(breaks because hostname reverse lookup does not resolve to our CAS server)
            $this->_cas_client->handleLogoutRequests( false );

            if ( $this->_cas_client->isProxy() ) {
                //Force all CAS callbacks to a specific URL
                $this->_cas_client->setCallbackURL( $this->base_uri . 'api/callback.php' );

                // Store PGT's in the database
                $this->_cas_client->setPGTStorageFile();

                // Accept any proxy chain
                // TODO: at some point we may need to tighten the proxy chain security
                $this->_cas_client->getAllowedProxyChains()->allowProxyChain( new \CAS_ProxyChain_Any() );
            }
        }

        /**
         * Returns the initialized CAS_Client object
         * @return \CAS_Client
         */
        final public function get_cas_client() {
            return $this->_cas_client;
        }

        /**
         * Update user meta based on cas:attributes response.
         * Called when a user is authenticated.
         *
         * @param string $ticket
         */
        final public function cas_authenticated( $ticket ) {
            // update the session id in the cookies, this is to prevent the session from being lost on subsequent wp_validate_auth_cookie calls
            $_COOKIE[ session_name() ] = session_id();

            //Email address is thekey user name
            $email = sanitize_email( $this->_cas_client->getUser() );

            //extract cas attributes
            $attrs = (array)$this->_cas_client->getAttributes();
            $guid  = array_key_exists( self::CAS_ATTRIBUTE_GUID, $attrs ) ? strtoupper( trim( (string)$attrs[ self::CAS_ATTRIBUTE_GUID ] ) ) : null;

            if ( $user = $this->get_user_by_guid( $guid ) ) {
                if ( strcasecmp( $user->user_login, $email ) != 0 )
                    $user = $this->set_user_login( $user, $email );
            }
            elseif ( $user = get_user_by( 'login', $email ) ) {
                update_user_meta( $user->ID, self::USER_META_GUID, $guid );
            }
            elseif ( $user = get_user_by( 'email', $email ) ) {
                $user = $this->set_user_login( $user, $email );
                update_user_meta( $user->ID, self::USER_META_GUID, $guid );
            }
            else {
                $user = $this->create_user( $guid, array(
                    'user_login' => $email,
                    'user_email' => $email,
                    'nickname'   => '',
                ) );
            }

            if ( $user instanceof \WP_User && $user->ID >= 0 ) {
                $first_name = array_key_exists( self::CAS_ATTRIBUTE_FIRST_NAME, $attrs ) ? trim( (string)$attrs[ self::CAS_ATTRIBUTE_FIRST_NAME ] ) : null;
                $last_name  = array_key_exists( self::CAS_ATTRIBUTE_LAST_NAME, $attrs ) ? trim( (string)$attrs[ self::CAS_ATTRIBUTE_LAST_NAME ] ) : null;
                $args       = array();
                if ( empty( $user->first_name ) && $first_name )
                    $args[ 'first_name' ] = $first_name;
                if ( empty( $user->last_name ) && $last_name )
                    $args[ 'last_name' ] = $last_name;
                if ( empty( $user->display_name ) && $first_name && $last_name )
                    $args[ 'display_name' ] = "{$first_name} {$last_name}";
                if ( empty( $user->user_nicename ) || $user->user_nicename != sanitize_title( $user->user_nicename ) )
                    $args[ 'user_nicename' ] = '';
                if ( ! empty( $args ) ) {
                    $args[ 'ID' ] = $user->ID;
                    wp_update_user( $args );
                }
            }
        }

        /**
         * Rewrites the WordPress login URL to use CAS and bypass wp-login.php
         *
         * @param string $login_url
         *
         * @return string Login URL
         */
        final public function login_url( $login_url ) {
            //Get the CAS login url, this has the service param in it already
            $cas_url = $this->_cas_client->getServerLoginURL();

            //This was interfering with the SSO flow because it stripped the ticket tag out
            if( !is_admin() ) {
                //return false;
            }

            if ( $login_query = parse_url( $login_url, PHP_URL_QUERY ) ) {
                $login_args = array();
                wp_parse_str( $login_query, $login_args );
                if ( array_key_exists( 'redirect_to', $login_args ) && ! empty( $login_args[ 'redirect_to' ] ) ) {
                    $redirect_to = remove_query_arg( 'ticket', $login_args[ 'redirect_to' ] );
                    $cas_url     = add_query_arg( 'service', $redirect_to, $cas_url );
                }
            }

            return $cas_url;
        }

        /**
         * Logout of CAS
         */
        final public function logout() {
            if ( $this->_cas_client && $this->_cas_client->isSessionAuthenticated() ) {
                $params = array();
                if(array_key_exists( 'redirect_to', $_REQUEST ) )
                    $params['service'] = stripslashes( $_REQUEST[ 'redirect_to' ] );
                $this->_cas_client->logout( $params );
            }
        }


        /**
         * Returns a user id for a user matching the meta information
         *
         * @param string $meta_key
         * @param string $meta_value
         *
         * @return int|null
         */
        public function get_user_by_meta( $meta_key, $meta_value ) {
            global $wpdb;
            $sql = "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = '%s' AND meta_value = '%s'";
            return $wpdb->get_var( $wpdb->prepare( $sql, $meta_key, $meta_value ) );
        }

        /**
         * Returns a WP_User object for the user matching the guid or null
         *
         * @param string $guid
         *
         * @return \WP_User|null
         */
        public function get_user_by_guid( $guid ) {
            if ( $userid = $this->get_user_by_meta( self::USER_META_GUID, $guid ) ) {
                return new \WP_User( $userid );
            }
            return null;
        }

        public function set_user_login( $user, $login ) {
            global $wpdb;
            $user = ( $user instanceof \WP_User ) ? $user : new \WP_User( (int)$user );
            if ( 0 >= $user->ID )
                return;

            //Remove user and old user_login from caches
            wp_cache_delete( $user->ID, 'users' );
            wp_cache_delete( $user->user_login, 'userlogins' );

            //Update user login
            $wpdb->update( $wpdb->users, array( 'user_login' => $login ), array( 'ID' => $user->ID ) );

            $user = new \WP_User( $user->ID );
            return $user;
        }

        public function get_user_guid( $user ) {
            $user = ( $user instanceof \WP_User ) ? $user : new \WP_User( (int)$user );
            if ( $user->ID > 0 ) {
                $guid = get_user_meta( $user->ID, self::USER_META_GUID, true );
                if ( preg_match( '/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i', $guid ) )
                    return $guid;
            }
            return 'GUEST';
        }

        /**
         * Creates a user in WordPress and assigns the GUID.
         *
         * This method creates a user with no role in the current site.
         *
         * @param string $guid GUID
         * @param array  $args User data
         *
         * @return WP_User|null
         */
        public function create_user( $guid, $args = array() ) {
            add_action( 'user_register', array( &$this, 'remove_user_capabilities' ), 0, 1 );
            $args[ 'user_pass' ] = md5( time() . $guid );
            $user_id             = wp_insert_user( $args );
            remove_action( 'user_register', array( &$this, 'remove_user_capabilities' ) );
            if ( is_wp_error( $user_id ) )
                return null;
            update_user_meta( $user_id, self::USER_META_GUID, $guid );
            return new \WP_User( $user_id );
        }

        /**
         * Removes all capabilities from the given user
         * callback for 'user_register' action when creating a new user
         * @see WPGCXPlugin::create_user()
         *
         * @param int $user_id
         */
        public function remove_user_capabilities( $user_id ) {
            $user = new \WP_User( $user_id );
            $user->remove_all_caps();
        }

        public function user_activate() {
            global $wpdb;
            auth_redirect();
            $blog_id = 1;
            $key     = array_key_exists( 'key', $_REQUEST ) ? stripslashes( $_REQUEST[ 'key' ] ) : null;
            if ( $key ) {
                $signup = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->signups} WHERE activation_key = %s", $key ) );
                if ( ! empty( $signup ) ) {
                    $meta = maybe_unserialize( $signup->meta );
                    if ( ! empty( $meta[ 'add_to_blog' ] ) ) {
                        $user = wp_get_current_user();

                        $blog_id = (int)$meta[ 'add_to_blog' ];
                        $role    = $meta[ 'new_role' ];

                        add_user_to_blog( $blog_id, $user->ID, $role );
                    }
                    $wpdb->delete( $wpdb->signups, array( 'activation_key' => $key ) );
                }
            }

            wp_redirect( get_site_url( $blog_id ) );
        }

        /**
         * Redirect the Add Existing user screen to our invite users admin page
         *
         * @param stdClass $screen Screen object
         */
        public function redirect_on_add_user_screen( $screen ) {
            if ( $screen->id == 'user' && $screen->action == 'add' ) {
                wp_redirect( admin_url( '/users.php?page=add-user' ) );
                exit();
            }
            return $screen;
        }

        /**
         * Remove the Add New submenu from the Users menu.
         */
        function remove_add_user_submenu() {
            remove_submenu_page( 'users.php', 'user-new.php' );
        }

        function add_user_page() {
            include( plugin_dir_path( __FILE__ ) . 'admin/add-user.php' );
        }

        function add_users_admin() {
            if ( isset( $_POST[ 'action' ] ) && 'createuser' == $_POST[ 'action' ] ) {
                check_admin_referer( 'create-user', '_wpnonce_create-user' );

                $email = sanitize_email( $_POST[ 'email' ] );
                $role  = $_POST[ 'role' ];
                if ( is_email( $email ) && ( $user = get_user_by( 'email', $email ) ) ) {
                    if ( add_user_to_blog( get_current_blog_id(), $user->ID, $role ) )
                        wp_redirect( add_query_arg( array( 'update' => 'useradded' ), 'users.php?page=add-user' ) );
                    else
                        wp_redirect( add_query_arg( array( 'error' => 'unknown' ), 'users.php?page=add-user' ) );
                }
                else {
                    wpmu_signup_user( $email, $email, array( 'add_to_blog' => get_current_blog_id(), 'new_role' => $role ) );
                    wp_redirect( add_query_arg( array( 'update' => 'userpending' ), 'users.php?page=add-user' ) );
                }

            }
        }

    }

    CASLogin::singleton();
}
namespace {
    
    //Check here to see if this is a backend page (is_admin), a draft preview ($_GET['preview'])
    //or a Gravity Forms form preview ($_GET['gf_page'] = preview) and only runs these hooks on those pages
    if( is_admin() || isset($_GET['preview']) || (isset($_GET['gf_page']) && $_GET['gf_page'] === 'preview') ) {
        /**
         * Overrides the method to prevent WordPress from setting auth cookies
         *
         * @param int    $user_id
         * @param string $remember
         * @param string $secure
         */
        function wp_set_auth_cookie( $user_id, $remember = false, $secure = '' ) {
        }

        /**
         * Validates Authenticated CAS User
         *
         * @param string $cookie
         * @param string $scheme
         */
        function wp_validate_auth_cookie( $cookie = '', $scheme = '' ) {
            // determine which cookie is being used for the session
            if ( empty( $cookie ) )
                $cookie = is_ssl() ? SECURE_AUTH_COOKIE : AUTH_COOKIE;

            // reopen the session to address the async-upload hack that changes session cookies and then re-runs this code
            if ( ! empty( $_COOKIE[ $cookie ] ) && $_COOKIE[ $cookie ] != session_id() ) {
                session_commit();
                session_id( $_COOKIE[ $cookie ] );
                session_start();
            }

            //Get the cas client
            $cas_client = \GlobalTechnology\CentralAuthenticationService\CASLogin::singleton()->get_cas_client();

            // check to see if the user has authenticated with CAS yet
            ob_start();
            global $authenticated;
            try {
                $authenticated = $cas_client->isAuthenticated();
                ob_end_flush();
            } catch ( \CAS_Exception $e ) {
                $authenticated = false;
                ob_end_clean();
            }
            if ( $authenticated && $cas_client->hasAttribute( \GlobalTechnology\CentralAuthenticationService\CASLogin::CAS_ATTRIBUTE_GUID ) ) {
                // get the guid for the current user from CAS
                $guid = strtoupper( $cas_client->getAttribute( \GlobalTechnology\CentralAuthenticationService\CASLogin::CAS_ATTRIBUTE_GUID ) );

                // find the user id for the current guid
                $user = \GlobalTechnology\CentralAuthenticationService\CASLogin::singleton()->get_user_by_guid( $guid );

                // return the user id or false if the user doesn't exist
                return is_null( $user ) ? false : $user->ID;
            }

            // not a valid CAS session, so return false
            return false;
        }
    }
}