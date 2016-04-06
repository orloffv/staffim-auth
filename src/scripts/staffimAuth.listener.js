'use strict';
(function() {
    angular.module('staffimAuth')
        .run(authListener);

    authListener.$inject = ['$rootScope', '$state', 'SAStateEncoder', 'SAService', 'SUNotify', 'SA_EVENTS'];
    function authListener($rootScope, $state, stateEncoder, SAService, SUNotify, SA_EVENTS) {
        $rootScope.$on(SA_EVENTS.ACCESS_TOKEN_EXPIRED, authError);

        function authError() {
            if (SAService.hasAccessToken()) {
                SAService.logout();
                SUNotify.warning('Ошибка авторизации. Попробуйте войти повторно');
                $state.go('public.login', {backstate: stateEncoder.encode($state)});
            }
        }
    }
})();
