(function(){
    angular.module('staffimAuth', []);
})();

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

'use strict';
(function() {
    angular.module('staffimAuth')
        .controller('SALoginController', SALoginController);

    SALoginController.$inject = ['SAService', '$state', '$stateParams'];
    function SALoginController(SAService, $state, $stateParams) {
        var vm = this;
        vm.credentials = {
            username: '',
            password: ''
        };
        vm.login = login;

        function login(credentials) {
            return SAService
                .login(credentials.username, credentials.password)
                .then(function() {
                    return $state.go($state.current, $stateParams, {reload: true});
                })
                .catch(function() {
                    vm.credentials = {
                        username: credentials.username,
                        password: credentials.password
                    };
                });
        }
    }
})();

'use strict';
(function() {
    angular.module('staffimAuth')
        .run(authListener);

    authListener.$inject = ['$rootScope', '$state', 'SAStateEncoder', 'SAService', 'toastr', 'SA_EVENTS'];
    function authListener($rootScope, $state, stateEncoder, SAService, toastr, SA_EVENTS) {
        $rootScope.$on(SA_EVENTS.ACCESS_TOKEN_EXPIRED, authError);

        function authError() {
            if (SAService.hasAccessToken()) {
                SAService.logout();
                toastr.warning('Ошибка авторизации. Попробуйте войти повторно');
                $state.go('public.login', {backstate: stateEncoder.encode($state)});
            }
        }
    }
})();

'use strict';
(function() {
    angular.module('staffimAuth')
        .run(stateChangeStart)
        .config(authRouter);

    authRouter.$inject = ['$stateProvider', '$urlRouterProvider'];
    function authRouter($stateProvider, $urlRouterProvider) {
        $stateProvider
            .state('public', {
                abstract: true,
                templateUrl: '/staffim-auth/layout-public.html'
            })
            .state('public.login', {
                title: 'Вход',
                url: '/login?backstate',
                templateUrl: '/staffim-auth/login.html',
                controller: 'SALoginController',
                controllerAs: 'vm',
                data: {
                    permissions: {
                        only: ['ANONYMOUS'],
                        redirectTo: 'auth.home'
                    },
                    bodyClass: 'login-content'
                }
            })
        ;

        $urlRouterProvider.when('/logout', logoutRoute);
    }

    logoutRoute.$inject = ['$state', 'SAService'];
    function logoutRoute($state, SAService) {
        SAService.logout();

        return $state.go('public.login');
    }

    stateChangeStart.$inject = ['$rootScope', 'SUPageService', 'SAStateEncoder', '$state', 'SAService'];
    function stateChangeStart($rootScope, pageService, stateEncoder, $state, SAService) {
        $rootScope.$on('$stateChangeStart', function(event, toState, toParams) {
            pageService.stateStatus = 'loading';
            if (SAService.isValidAccessToken()) {
                if (toState.name === 'public.login' || toState.name === 'public.recovery') {
                    event.preventDefault();
                    var stateData = stateEncoder.decode(toParams.backstate),
                        findBackState;
                    if (!stateData || !stateData.name) {
                        stateData = {
                            name: 'auth.home'
                        };
                    } else if (stateData.name && (findBackState = $state.get(stateData.name))) {
                        if (findBackState.data && findBackState.data.error === true) {
                            stateData = {
                                name: 'auth.home'
                            };
                        }
                    }

                    $state.go(stateData.name, stateData.params);
                }
            }
        });
    }
})();

'use strict';
(function() {
    angular.module('staffimAuth')
        .factory('SAService', SAService);

    SAService.$inject = ['$http', '$rootScope', 'store', '$q', 'jQuery', 'jwtHelper', 'CONFIG', 'userModel'];
    function SAService($http, $rootScope, store, $q, jQuery, jwtHelper, CONFIG, userModel) {
        var service = {},
            credentials;

        service.clearCredentials = clearCredentials;
        service.loadCredentials = loadCredentials;
        service.getCredentials = getCredentials;
        service.hasCredentials = hasCredentials;
        service.setCredentials = setCredentials;

        service.login = login;
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

        return service;

        function login(username, password) {
            return service.requestAccessToken(username, password);
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

        function loadCredentials(force) {
            if (service.hasCredentials() && !force) {
                var deferred = $q.defer();
                deferred.resolve(service.getCredentials());

                return deferred.promise;
            }

            return userModel.$find('current').$asPromise()
                .then(function(data) {
                    service.setCredentials(data);

                    return data;
                });
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

'use strict';
(function() {
    angular.module('staffimAuth')
        .service('SAStateEncoder', SAStateEncoder);

    SAStateEncoder.$inject = ['SAJsonEncoder'];
    function SAStateEncoder(jsonEncoder) {
        var encoder = {
            encode: function(state) {
                if (!angular.isObject(state)) {
                    return '';
                }

                var stateObject = state;

                if (angular.isObject(state.current) && angular.isObject(state.params)) {
                    stateObject = {
                        name: state.current.name,
                        params: state.params
                    };
                }

                return jsonEncoder.encode({
                    name: stateObject.name,
                    params: stateObject.params
                });
            },
            decode: function(encodedState) {
                return jsonEncoder.decode(encodedState);
            }
        };

        return encoder;
    }
})();

'use strict';
(function() {
    angular.module('staffimAuth')
        .service('SAJsonEncoder', function() {
            var SAJsonEncoder = {
                encode: function(object) {
                    if (!angular.isObject(object)) {
                        return '';
                    }

                    var objectString = JSON.stringify(object);

                    return window.btoa(window.unescape(encodeURIComponent(objectString)));
                },
                decode: function(encodedState) {
                    var result;

                    if (!angular.isString(encodedState)) {
                        return encodedState;
                    }

                    var stateString = decodeURIComponent(window.escape(window.atob(encodedState)));
                    try {
                        result = JSON.parse(stateString);
                    } catch (e) {}

                    return result;
                },
                isEncoded: function(object) {
                    try {
                        var result = this.decode(object);

                        if (result === object) {
                            return false;
                        }

                        return true;
                    } catch (e) {
                        return false;
                    }
                }
            };

            return SAJsonEncoder;
        });
})();

'use strict';
(function() {
    angular.module('staffimAuth')
        .directive('saState', saState);

    saState.$inject = ['Permission', '$state'];
    function saState(Permission, $state) {
        var directive = {
            restrict: 'A',
            link: link
        };

        return directive;

        function link(scope, element, attrs) {
            var stateConfig = getStateConfiguration(attrs.uiSref);

            if (stateConfig.data && stateConfig.data.permissions)
            {
                var roles = getRolesFromStateConfiguration(stateConfig);

                var customAttributes = {};
                var rule = (stateConfig.data.permissions.only ? directives.only : directives.except);
                customAttributes[rule] = roles;

                checkPermissions(rule, element, customAttributes, Permission);
            }
        }

        function getStateConfiguration(stateName){
            var states = $state.get();
            var stateConfiguration = states.filter(function (route) {
                return (route.name === stateName);
            });

            if(stateConfiguration.length === 0) {
                throw new Error('State is not defined in the router config');
            }

            return stateConfiguration[0];
        }

        function getRolesFromStateConfiguration(stateConfig) {
            var roles = (stateConfig.data.permissions.only ? stateConfig.data.permissions.only : stateConfig.data.permissions.except);

            return roles.join(',');
        }
    }

    function checkPermissions(directiveName, element, attrs, Permission) {
        var roleMap = {};
        var roles = attrs[directiveName].replace(/\[|]|'/gi, '').split(',');
        roleMap[(directiveName === directives.only ? 'only' : 'except')] = roles;

        var behavior = (attrs.rpBehavior ? attrs.rpBehavior : 'hide');
        validateBehaviorParams(behavior);

        var authorizing = Permission.authorize(roleMap, null);
        authorizing.then(null, function() {
            //authorize rejected -> apply behavior to element
            elementBehaviors[behavior](element);
        });
    }

    function validateBehaviorParams(behavior) {
        if(!elementBehaviors[behavior]) {
            throw new Error(EXCEPTIONS.UNDEFINED_RP_BEHAVIOR);
        }
    }

    var directives = {
        only: 'permission-only',
        except: 'permission-except'
    };

    var elementBehaviors = {
        'hide': function(element) {
            element.addClass('ng-hide');
        },
        'disable': function(element) {
            element.attr('disabled', 'disabled');
        }
    }
})();

(function () {
    'use strict';

    angular
        .module('staffimAuth')
        .directive('permissionOnly', ['$log', 'Permission', function ($log, Permission) {
            return {
                restrict: 'A',
                link: function (scope, element, attrs) {
                    try {
                        Permission
                            .authorize({only: attrs.permissionOnly.replace(/\s/g, '').split(',')})
                            .then(function () {
                                element.removeClass('ng-hide');
                            })
                            .catch(function () {
                                element.addClass('ng-hide');
                            });
                    } catch (e) {
                        element.addClass('ng-hide');
                        $log.error(e.message);
                    }
                }
            };
        }])

        .directive('permissionExcept', ['$log', 'Permission', function ($log, Permission) {
            return {
                restrict: 'A',
                link: function (scope, element, attrs) {
                    try {
                        Permission
                            .authorize({except: attrs.permissionExcept.replace(/\s/g, '').split(',')})
                            .then(function () {
                                element.removeClass('ng-hide');
                            })
                            .catch(function () {
                                element.addClass('ng-hide');
                            });
                    } catch (e) {
                        element.addClass('ng-hide');
                        $log.error(e.message);
                    }
                }
            };
        }]);
}());

angular.module('staffimAuth').run(['$templateCache', function($templateCache) {
  'use strict';

  $templateCache.put('/staffim-auth/layout-public.html',
    "<div class=\"container\" ui-view></div>\n"
  );


  $templateCache.put('/staffim-auth/login.html',
    "<form class=\"lc-block toggled\" ng-submit=\"vm.login(vm.credentials)\" onsubmit=\"return false;\" name=\"loginForm\">\n" +
    "    <div class=\"input-group m-b-20\">\n" +
    "        <span class=\"input-group-addon\"><i class=\"zmdi zmdi-account\"></i></span>\n" +
    "        <div class=\"fg-line\">\n" +
    "            <input type=\"email\" name=\"username\" class=\"form-control\" placeholder=\"E-mail\" autofocus autofill ng-model=\"vm.credentials.username\" required>\n" +
    "        </div>\n" +
    "    </div>\n" +
    "\n" +
    "    <div class=\"input-group m-b-20\">\n" +
    "        <span class=\"input-group-addon\"><i class=\"zmdi zmdi-male\"></i></span>\n" +
    "        <div class=\"fg-line\">\n" +
    "            <input type=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Пароль\" autofill ng-model=\"vm.credentials.password\" required>\n" +
    "        </div>\n" +
    "    </div>\n" +
    "\n" +
    "    <div class=\"clearfix\"></div>\n" +
    "    <button class=\"btn btn-login btn-danger btn-float\" ng-disabled=\"loginForm.$invalid\" type=\"submit\">\n" +
    "        <i class=\"zmdi zmdi-arrow-forward\"></i>\n" +
    "    </button>\n" +
    "</form>\n"
  );

}]);
