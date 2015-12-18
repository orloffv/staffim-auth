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
            var state = attrs.uiSref;
            if (!_.has(attrs, 'uiSref')) {
                if (element.find('a[ui-sref]').length) {
                    state = element.find('a').attr('ui-sref');
                }
            }
            var stateConfig = getStateConfiguration(state);

            if (stateConfig.data && stateConfig.data.permissions)
            {
                var roles = getRolesFromStateConfiguration(stateConfig);

                var customAttributes = {};
                var rule = (stateConfig.data.permissions.only ? directives.only : directives.except);
                customAttributes[rule] = roles;

                checkPermissions(rule, element, customAttributes, Permission);
            }
        }

        function getStateConfiguration(stateName) {
            var states = $state.get();
            var stateConfiguration = states.filter(function (route) {
                return (route.name === stateName);
            });

            if(stateConfiguration.length === 0) {
                throw new Error('State ' + stateName + ' is not defined in the router config');
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
