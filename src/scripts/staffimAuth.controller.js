'use strict';
(function() {
    angular.module('staffimAuth')
        .controller('SALoginController', SALoginController)
        .controller('SARecoveryController', SARecoveryController)
        .controller('SARecoveryPasswordController', SARecoveryPasswordController);

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
                .then(
                    function() {
                        return $state.go('auth.home');
                    },
                    function() {
                        toastr.error('Не удалось войти. Неверные данные для входа');

                        vm.credentials = {
                            username: credentials.username,
                            password: credentials.password
                        };
                    }
                );
        }
    }

    SARecoveryController.$inject = ['SAService', '$state', 'toastr'];
    function SARecoveryController(SAService, $state, toastr) {
        var vm = this;
        vm.credentials = {
            username: ''
        };
        vm.recovery = recovery;

        function recovery(credentials) {
            return SAService
                .recovery(credentials.username)
                .then(
                    function() {
                        toastr.success('Инструкция по восстановлению пароля отправлена вам на электронную почту');

                        return $state.go('public.login');
                    },
                    function() {
                        toastr.error('Не удалось отправить письмо для восстановления пароля');

                        vm.credentials = {
                            username: credentials.username
                        };
                    }
                );
        }
    }

    SARecoveryPasswordController.$inject = ['SAService', '$state', 'toastr', 'recovery'];
    function SARecoveryPasswordController(SAService, $state, toastr, recovery) {
        var vm = this;
        vm.credentials = {
            password: ''
        };
        vm.recovery = recovery;
        vm.recoveryPassword = recoveryPassword;

        function recoveryPassword(credentials) {
            return SAService
                .recoveryPassword(recovery.id, credentials.password)
                .then(
                    function() {
                        toastr.success('Пароль успешно изменен');

                        return $state.go('public.login');
                    },
                    function() {
                        toastr.error('Не удалось изменить пароль');

                        vm.credentials = {
                            password: credentials.password
                        };
                    }
                );
        }
    }
})();
