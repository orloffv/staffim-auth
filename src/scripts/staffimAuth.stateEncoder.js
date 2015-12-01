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
