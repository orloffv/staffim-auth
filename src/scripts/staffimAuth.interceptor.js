'use strict';
(function() {
    angular.module('staffimAuth')
        .config(accessTokenInterceptor);

    accessTokenInterceptor.$inject = ['$httpProvider', 'jwtInterceptorProvider'];
    function accessTokenInterceptor($httpProvider, jwtInterceptorProvider) {
        jwtInterceptorProvider.urlParam = 'token';
        jwtInterceptorProvider.tokenGetter = tokenGetter;

        tokenGetter.$inject = ['SAService', 'config', 'CONFIG'];
        function tokenGetter(SAService, config, CONFIG) {
            if (config.url.indexOf(CONFIG.apiUrl) !== 0) {
                return null;
            }
            var accessToken = SAService.getAccessToken();
            if (!accessToken) {
                return false;
            }

            if (!SAService.isValidAccessToken() && SAService.hasRefreshToken()) {
                return SAService
                    .requestRefreshToken()
                    .then(function() {
                        return SAService.getAccessToken();
                    });
            } else {
                return accessToken;
            }
        }

        $httpProvider.interceptors.push('jwtInterceptor');
    }
})();
