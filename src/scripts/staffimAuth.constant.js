'use strict';
(function() {
    angular.module('staffimAuth')
        .constant('SA_EVENTS', {
            //LOGIN_SUCCESS: 'auth-login-success',
            //LOGIN_FAILED: 'auth-login-failed',
            //LOGOUT_SUCCESS: 'auth-logout-success',
            //SESSION_TIMEOUT: 'auth-session-timeout',
            //NOT_AUTHENTICATED: 'auth-not-authenticated',
            //NOT_AUTHORIZED: 'auth-not-authorized'
            ACCESS_TOKEN_EXPIRED: 'access-token-expired'
        });
})();
