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
            .state('public.recovery', {
                title: 'Восстановление пароля',
                url: '/recovery',
                templateUrl: '/staffim-auth/recovery.html',
                controller: 'SARecoveryController',
                controllerAs: 'vm',
                data: {
                    permissions: {
                        only: ['ANONYMOUS'],
                        redirectTo: 'auth.home'
                    },
                    bodyClass: 'login-content'
                }
            })
            .state('public.recovery_password', {
                title: 'Изменение пароля',
                url: '/recovery/{recovery:[0-9a-fA-F]{24}}',
                templateUrl: '/staffim-auth/recoveryPassword.html',
                controller: 'SARecoveryPasswordController',
                controllerAs: 'vm',
                resolve: {
                    recovery: ['SAService', '$q', '$stateParams', function(SAService, $q, $stateParams) {
                        var deferred = $q.defer();

                        SAService.loadRecovery($stateParams.recovery)
                            .then(function() {
                                deferred.resolve({id: $stateParams.recovery, valid: true});
                            })
                            .catch(function() {
                                deferred.resolve({id: $stateParams.recovery, valid: false});
                            });

                        return deferred.promise;
                    }]
                },
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
