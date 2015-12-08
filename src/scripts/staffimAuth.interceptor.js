'use strict';
(function() {
    angular.module('staffimAuth')
        .factory('SAhttpInterceptor', SAhttpInterceptor)
        .config(setInterceptor);

    SAhttpInterceptor.$inject = ['$rootScope', 'SA_EVENTS', '$q'];
    function SAhttpInterceptor($rootScope, SA_EVENTS, $q) {
        var service = {};

        service.responseError = responseError;

        return service;

        function responseError(response) {
            if (response.status === 401) {
                $rootScope.$broadcast(SA_EVENTS.ACCESS_TOKEN_EXPIRED, response);
            }

            return $q.reject(response);
        }
    }

    setInterceptor.$inject = ['$httpProvider'];
    function setInterceptor($httpProvider) {
        $httpProvider.interceptors.push('SAhttpInterceptor');
    }
})();
