'use strict';
(function() {
    angular.module('staffimAuth')
        .controller('SALoginController', SALoginController);

    SALoginController.$inject = ['SAService', '$state'];
    function SALoginController(SAService, $state) {
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
