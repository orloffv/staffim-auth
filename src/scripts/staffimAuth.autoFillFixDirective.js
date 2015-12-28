(function () {
    'use strict';

    angular
        .module('staffimAuth')
        .directive('saFormAutofillFix', function() {
            return function(scope, elem) {
                // Fixes Chrome bug: https://groups.google.com/forum/#!topic/angular/6NlucSskQjY
                elem.prop('method', 'POST');

                // Fix autofill issues where Angular doesn't know about autofilled inputs
                setTimeout(function() {
                    elem.find('input, textarea, select').trigger('input').trigger('change').trigger('keydown');
                }, 200);
            };
        });
}());
