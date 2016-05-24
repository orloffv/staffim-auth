'use strict';
(function() {
    angular.module('staffimAuth')
        .factory('SAService', SAService);

    SAService.$inject = ['$http', '$rootScope', 'store', '$q', 'jQuery', 'jwtHelper', 'CONFIG', 'userModel', '$injector', 'SUAnalytic', 'SULogger'];
    function SAService($http, $rootScope, store, $q, jQuery, jwtHelper, CONFIG, userModel, $injector, SUAnalytic, SULogger) {
        var service = {},
            credentials;

        service.clearCredentials = clearCredentials;
        service.loadCredentials = loadCredentials;
        service.getCredentials = getCredentials;
        service.hasCredentials = hasCredentials;
        service.setCredentials = setCredentials;

        service.login = login;
        service.recovery = recovery;
        service.loadRecovery = loadRecovery;
        service.recoveryPassword = recoveryPassword;
        service.logout = logout;
        service.hasAccessToken = hasAccessToken;
        service.getAccessToken = getAccessToken;
        service.setAccessToken = setAccessToken;
        service.requestRefreshToken = requestRefreshToken;
        service.hasRefreshToken = hasRefreshToken;
        service.getRefreshToken = getRefreshToken;
        service.setRefreshToken = setRefreshToken;
        service.isAuthorized = isAuthorized;
        service.isNotAuthorized = isNotAuthorized;
        service.requestAccessToken = requestAccessToken;
        service.isValidAccessToken = isValidAccessToken;
        service.isAllowed = isAllowed;
        service.getCredentialsAnalyticInitData = getCredentialsAnalyticInitData;

        return service;

        function login(username, password) {
            return service.requestAccessToken(username, password);
        }

        function loadRecovery(recoveryId) {
            return $http.get(
                CONFIG.apiUrl + '/password_recovery/' + recoveryId,
                {
                    skipAuthorization: true
                });
        }

        function recovery(username) {
            return $http.post(
                CONFIG.apiUrl + '/password_recovery',
                {
                    email: username
                },
                {
                    skipAuthorization: true
                });
        }

        function recoveryPassword(recoveryId, password) {
            return $http.post(
                CONFIG.apiUrl + '/password_recovery/' + recoveryId,
                {
                    password: password
                },
                {
                    skipAuthorization: true
                });
        }

        function requestAccessToken(username, password) {
            return $http.post(
                CONFIG.apiUrl + '/login_check',
                jQuery.param({_username: username, _password: password}),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    skipAuthorization: true
                })
                .then(function(response) {
                    if (response.data) {
                        service.setAccessToken(response.data.token);
                    }

                    return response;
                });
        }

        function isAuthorized() {
            if (service.isValidAccessToken()) {
                return service.loadCredentials();
            }

            return $q.reject();
        }

        function isValidAccessToken() {
            return service.hasAccessToken() && !jwtHelper.isTokenExpired(service.getAccessToken());
        }

        function isNotAuthorized() {
            if (service.isValidAccessToken()) {
                var deferred = $q.defer();

                service.loadCredentials()
                    .then(function() {
                        deferred.reject();
                    })
                    .catch(function() {
                        deferred.resolve();
                    });

                return deferred.promise;
            }

            return true;
        }

        function requestRefreshToken() {
            /*
             return $http({
             url: '/delegation',
             skipAuthorization: true,
             method: 'POST',
             data: {
             grant_type: 'refresh_token',
             refresh_token: refreshToken
             }
             }).then(function(response) {

             var id_token = response.data.id_token;
             localStorage.setItem('id_token', id_token);
             return id_token;
             });
             */
        }

        function hasAccessToken() {
            return Boolean(service.getAccessToken());
        }

        function getAccessToken() {
            return store.get('access_token');
        }

        function setAccessToken(token) {
            store.set('access_token', token);
        }

        function hasRefreshToken() {
            return Boolean(service.getRefreshToken());
        }

        function getRefreshToken() {
            return store.get('refresh_token');
        }

        function setRefreshToken(token) {
            store.set('refresh_token', token);
        }

        function logout() {
            service.setAccessToken(null);
            service.setRefreshToken(null);
            service.clearCredentials();
        }

        function loadCredentials(force, params) {
            if (service.hasCredentials() && !force) {
                var deferred = $q.defer();
                deferred.resolve(service.getCredentials());

                return deferred.promise;
            }

            var currentParams = {};
            if (!_.isUndefined(params)) {
                currentParams = params;
            } else if (userModel.getDefaultParams) {
                currentParams = userModel.getDefaultParams();
            }

            return userModel.$find('current', currentParams).$asPromise()
                .then(function(data) {
                    if (data.getModelName && data.getModelName()) {
                        var injectorModel = $injector.get(data.getModelName());
                        data = injectorModel.$build().$decode(data.$response.data);
                    }
                    service.setCredentials(data);
                    SUAnalytic.init(service.getCredentialsAnalyticInitData());
                    SULogger.init(service.getCredentialsAnalyticInitData());

                    return data;
                })
                .catch(function(errorResponse) {
                    service.logout();

                    return $q.reject(errorResponse);
                });
        }

        function getCredentialsAnalyticInitData() {
            var credentials = this.getCredentials();
            if (credentials && credentials.getAnalyticInitData) {
                return credentials.getAnalyticInitData();
            }

            return {};
        }

        function getCredentials() {
            return credentials;
        }

        function hasCredentials() {
            return !!service.getCredentials();
        }

        function setCredentials(data) {
            credentials = data;
            $rootScope.globals = {
                credentials: credentials
            };
        }

        function clearCredentials() {
            service.setCredentials(null);
        }

        function isAllowed(role) {
            return service.isAuthorized()
                .then(function() {
                    var find = _.find(service.getCredentials().roles, function(currentRole) {
                        return ('ROLE_' + role) === currentRole;
                    });

                    var deferred = $q.defer();

                    if (find) {
                        deferred.resolve();
                    } else {
                        deferred.reject();
                    }

                    return deferred.promise;
                });
        }
    }
})();
