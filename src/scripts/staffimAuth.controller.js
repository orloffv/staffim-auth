'use strict';
(function() {
    angular.module('staffimAuth')
        .controller('SALoginController', SALoginController)
        .controller('SARecoveryController', SARecoveryController)
        .controller('SARecoveryPasswordController', SARecoveryPasswordController);

    SALoginController.$inject = ['SAService', '$state', 'SUNotify'];
    function SALoginController(SAService, $state, SUNotify) {
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
                        SUNotify.error('Не удалось войти. Неверные данные для входа');

                        vm.credentials = {
                            username: credentials.username,
                            password: credentials.password
                        };
                    }
                );
        }
    }

    SARecoveryController.$inject = ['SAService', '$state', 'SUNotify'];
    function SARecoveryController(SAService, $state, SUNotify) {
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
                        SUNotify.success('Инструкция по восстановлению пароля отправлена вам на электронную почту');

                        return $state.go('public.login');
                    },
                    function() {
                        SUNotify.error('Не удалось отправить письмо для восстановления пароля');

                        vm.credentials = {
                            username: credentials.username
                        };
                    }
                );
        }
    }

    SARecoveryPasswordController.$inject = ['SAService', '$state', 'SUNotify', 'recovery'];
    function SARecoveryPasswordController(SAService, $state, SUNotify, recovery) {
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
                        SUNotify.success('Пароль успешно изменен');

                        return $state.go('public.login');
                    },
                    function() {
                        SUNotify.error('Не удалось изменить пароль');

                        vm.credentials = {
                            password: credentials.password
                        };
                    }
                );
        }
    }
})();
