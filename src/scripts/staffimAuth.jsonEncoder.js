'use strict';
(function() {
    angular.module('staffimAuth')
        .service('SAJsonEncoder', function() {
            var SAJsonEncoder = {
                encode: function(object) {
                    if (!angular.isObject(object)) {
                        return '';
                    }

                    var objectString = JSON.stringify(object);

                    return window.btoa(window.unescape(encodeURIComponent(objectString)));
                },
                decode: function(encodedState) {
                    var result;

                    if (!angular.isString(encodedState)) {
                        return encodedState;
                    }

                    var stateString = decodeURIComponent(window.escape(window.atob(encodedState)));
                    try {
                        result = JSON.parse(stateString);
                    } catch (e) {}

                    return result;
                },
                isEncoded: function(object) {
                    try {
                        var result = this.decode(object);

                        if (result === object) {
                            return false;
                        }

                        return true;
                    } catch (e) {
                        return false;
                    }
                }
            };

            return SAJsonEncoder;
        });
})();
