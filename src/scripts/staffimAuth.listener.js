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
