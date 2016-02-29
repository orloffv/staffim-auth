'use strict';
(function() {
    angular.module('staffimAuth')
        .controller('SALoginController', SALoginController);

    SALoginController.$inject = ['SAService', '$state', 'toastr'];
    function SALoginController(SAService, $state, toastr) {
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
                    return $state.go('auth.home');
                },
                function() {
                    toastr.error('Не удалось войти. Неверные данные для входа');

                    vm.credentials = {
                        username: credentials.username,
                        password: credentials.password
                    };
                });
        }
    }
})();
