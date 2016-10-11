<?php

/** Requiere the JWT library. */
use \Firebase\JWT\JWT;

/**
 * The public-facing functionality of the plugin.
 *
 * @since      1.0.1
 */

/**
 * The public-facing functionality of the plugin.
 *
 * Defines the plugin name, version, and two examples hooks for how to
 * enqueue the admin-specific stylesheet and JavaScript.
 *
 * @author     Valery Lavrentiev <lavsurgut@gmail.com>
 */
class Jwt_Auth_Ext_Public
{
    /**
     * The ID of this plugin.
     *
     * @since    1.0.0
     *
     * @var string The ID of this plugin.
     */
    private $plugin_name;

    /**
     * The version of this plugin.
     *
     * @since    1.0.0
     *
     * @var string The current version of this plugin.
     */
    private $version;

    /**
     * The namespace to add to the api calls.
     *
     * @var string The namespace to add to the api call
     */
    private $namespace;

    /**
     * Store errors to display if the JWT is wrong
     *
     * @var WP_Error
     */
    private $jwt_error = null;
    /**
     * The JWT secret key.
     *
     * @var string The namespace to add to the api call
     */

    private $secret_key = null;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     *
     * @param string $plugin_name The name of the plugin.
     * @param string $version     The version of this plugin.
     */
    public function __construct($plugin_name, $version)
    {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
        $this->namespace = $this->plugin_name.'/v'.intval($this->version);
        $this->secret_key = defined('JWT_AUTH_EXT_SECRET_KEY') ? JWT_AUTH_EXT_SECRET_KEY : false;
    }

    /**
     * Add the endpoints to the API
     */
    public function add_api_routes()
    {
        register_rest_route($this->namespace, 'login', [
            'methods' => 'POST',
            'callback' => array($this, 'login_user'),
            'permission_callback' => array($this, 'validate_secret_key')
        ]);

        register_rest_route($this->namespace, 'register', array(
            'methods' => 'POST',
            'callback' => array($this, 'register_user'),
            'permission_callback' => array($this, 'validate_secret_key')
        ));

        register_rest_route($this->namespace, 'token/validate', array(
            'methods' => 'POST',
            'callback' => array($this, 'validate_token'),
        ));

    }

    /**
     * Add CORs suppot to the request.
     */
    public function add_cors_support()
    {
        $enable_cors = defined('JWT_AUTH_EXT_CORS_ENABLE') ? JWT_AUTH_EXT_CORS_ENABLE : false;
        if ($enable_cors) {
            $headers = apply_filters('jwt_auth_ext_cors_allow_headers', 'Access-Control-Allow-Headers, Content-Type, Authorization');
            header(sprintf('Access-Control-Allow-Headers: %s', $headers));
        }
    }

    /**
     * Perform validation checks
     *
     * @return WP_Error|boolean
     */

    public function validate_secret_key () {
        /** First thing, check the secret key if not exist return a error*/
        if (!$this->secret_key) {
            return new WP_Error(
                'jwt_auth_ext_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth-ext'),
                array(
                    'status' => 403,
                )
            );
        } else {
            return true;
        }

    }

    /**
     * Form response for the user
     *
     * @param string $token
     * @param Wp_User $user
     *
     * @return WP_Error|WP_REST_Response $response
     */

    private function form_response ($token, $user) {
        /** The token is signed, now create the object with no sensible user data to the client*/
        $data = array(
            'token' => $token,
            'user_first_name' => $user->first_name,
            'user_login' => $user->user_login,
            'user_id' => $user->ID
        );
        /** Valid credentials, the user exists create the according Token and return it */
        return apply_filters('jwt_auth_ext_token_before_dispatch', $data, $user);
    }

    /**
     * Get the user and password in the request body, login and generate a JWT
     *
     * @param WP_REST_Request $request
     *
     * @return WP_Error|WP_REST_Response $response
     */

    public function login_user ($request) {

        $username = $request->get_param('username');
        $password = $request->get_param('password');

        /** Try to authenticate the user with the passed credentials*/
        $user = wp_authenticate($username, $password);

        /** If the authentication fails return a error*/
        if (is_wp_error($user)) {
            return new WP_Error(
                'jwt_auth_ext_failed',
                __('Invalid Credentials.', 'wp-api-jwt-auth-ext'),
                array(
                    'status' => 403,
                )
            );
        }

        $token = $this->generate_token($user);

        return $this->form_response($token, $user);

    }
    /**
     * Get the new user in the request body, register and generate a JWT
     *
     * @param WP_REST_Request $request
     *
     * @return WP_Error| WP_REST_Response $response
     */

    public function register_user ($request) {

        $userdata = array(
            'user_login'  =>  $request->get_param('username'),
            'user_email'    =>  $request->get_param('user_email'),
            'first_name'    =>  $request->get_param('first_name'),
            'last_name'    =>  $request->get_param('last_name'),
            'user_pass'   =>  $request->get_param('password')
        );

        if (!get_user_by( 'email', $userdata['user_email']))
        {
            $user_id = wp_insert_user( $userdata );
        } else {
            return new WP_Error(
                'jwt_auth_ext_failed',
                __('User already exists.', 'wp-api-jwt-auth-ext'),
                array(
                    'status' => 403,
                )
            );
        }

        $user = get_userdata( $user_id );

        /** If the authentication fails return a error*/
        if (is_wp_error($user)) {
            return new WP_Error(
                'jwt_auth_ext_failed',
                __('Invalid Credentials.', 'wp-api-jwt-auth-ext'),
                array(
                    'status' => 403,
                )
            );
        }

        $token = $this->generate_token($user);

        return $this->form_response($token, $user);

    }

    /**
     * Get generate a JWT
     *
     * @param WP_User $user user to generate token for
     *
     * @return string $token generated token
     */
    private function generate_token($user)
    {
        $issuedAt = time();
        $notBefore = apply_filters('jwt_auth_ext_not_before', $issuedAt, $issuedAt);
        $expire = apply_filters('jwt_auth_ext_expire', $issuedAt + (DAY_IN_SECONDS * 7), $issuedAt);

        $token = array(
            'iss' => get_bloginfo('url'),
            'iat' => $issuedAt,
            'nbf' => $notBefore,
            'exp' => $expire,
            'data' => array(
                'user' => array(
                    'id' => $user->data->ID,
                ),
            ),
        );

        /** Let the user modify the token data before the sign. */
        $token = JWT::encode(apply_filters('jwt_auth_ext_token_before_sign', $token), $this->secret_key);

        /** Let the user modify the data before send it back */
        return $token;
    }

    /**
     * This is our Middleware to try to authenticate the user according to the
     * token send.
     *
     * @param (int|bool) $user Logged User ID
     *
     * @return (int|bool)
     */
    public function determine_current_user($user)
    {
        /*
         * if the request URI is for validate the token don't do anything,
         * this avoid double calls to the validate_token function.
         */
        $validate_uri = strpos($_SERVER['REQUEST_URI'], 'token/validate');
        if ($validate_uri > 0) {
            return $user;
        }

        $token = $this->validate_token(false);

        if (is_wp_error($token)) {
            if ($token->get_error_code() != 'jwt_auth_ext_no_auth_header') {
                /** If there is a error, store it to show it after see rest_pre_dispatch */
                $this->jwt_error = $token;
                return $user;
            } else {
                return $user;
            }
        }
        /** Everything is ok, return the user ID stored in the token*/
        return $token->data->user->id;
    }

    /**
     * Main validation function, this function try to get the Autentication
     * headers and decoded.
     *
     * @param bool $output
     *
     * @return WP_Error | Object
     */
    public function validate_token($output = true)
    {
        /*
         * Looking for the HTTP_AUTHORIZATION header, if not present just
         * return the user.
         */
        $auth = isset($_SERVER['HTTP_AUTHORIZATION']) ?  $_SERVER['HTTP_AUTHORIZATION'] : false;
        if (!$auth) {
            return new WP_Error(
                'jwt_auth_ext_no_auth_header',
                __('Authorization header not found.', 'wp-api-jwt-auth-ext'),
                array(
                    'status' => 403,
                )
            );
        }

        /*
         * The HTTP_AUTHORIZATION is present verify the format
         * if the format is wrong return the user.
         */
        list($token) = sscanf($auth, 'Bearer %s');
        if (!$token) {
            return new WP_Error(
                'jwt_auth_ext_bad_auth_header',
                __('Authorization header malformed.', 'wp-api-jwt-auth-ext'),
                array(
                    'status' => 403,
                )
            );
        }

        /** Check the Secret Key */
        if (is_wp_error( $this->validate_secret_key() ) ) {
            return $this->validate_secret_key();
        }

        /** Try to decode the token */
        try {
            $token = JWT::decode($token, $this->secret_key, array('HS256'));
            /** The Token is decoded now validate the iss */
            if ($token->iss != get_bloginfo('url')) {
                /** The iss do not match, return error */
                return new WP_Error(
                    'jwt_auth_ext_bad_iss',
                    __('The iss do not match with this server', 'wp-api-jwt-auth-ext'),
                    array(
                        'status' => 403,
                    )
                );
            }
            /** So far so good, validate the user id in the token */
            if (!isset($token->data->user->id)) {
                /** No user id in the token, abort!! */
                return new WP_Error(
                    'jwt_auth_ext_bad_request',
                    __('User ID not found in the token', 'wp-api-jwt-auth-ext'),
                    array(
                        'status' => 403,
                    )
                );
            }
            /** Everything looks good return the decoded token if the $output is false */
            if (!$output) {
                return $token;
            }
            /** If the output is true return an answer to the request to show it */
             return array(
                 'code' => 'jwt_auth_ext_valid_token',
                 'data' => array(
                     'status' => 200,
                 ),
             );
         } catch (Exception $e) {
            /** Something is wrong trying to decode the token, send back the error */
             return new WP_Error(
                 'jwt_auth_ext_invalid_token',
                 $e->getMessage(),
                 array(
                     'status' => 403,
                 )
             );
         }
    }

    /**
     * Filter to hook the rest_pre_dispatch, if the is an error in the request
     * send it, if there is no error just continue with the current request.
     *
     * @param $request
     */
    public function rest_pre_dispatch($request)
    {
        if (is_wp_error($this->jwt_error)) {
            return $this->jwt_error;
        }
        return $request;
    }
}
