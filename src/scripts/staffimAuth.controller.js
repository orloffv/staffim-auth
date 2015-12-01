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
