module.exports = function(grunt) {
    "use strict";

    grunt.initConfig({
        concat: {
            js: {
                src: [
                    'src/scripts/staffimAuth.module.js',
                    'src/scripts/staffimAuth.constant.js',
                    'src/scripts/staffimAuth.controller.js',
                    'src/scripts/staffimAuth.listener.js',
                    'src/scripts/staffimAuth.route.js',
                    'src/scripts/staffimAuth.service.js',
                    'src/scripts/staffimAuth.tokenInterceptor.js',
                    'src/scripts/staffimAuth.interceptor.js',
                    'src/scripts/staffimAuth.stateEncoder.js',
                    'src/scripts/staffimAuth.jsonEncoder.js',
                    'src/scripts/staffimAuth.stateDirective.js',
                    'src/scripts/staffimAuth.permissionDirective.js',
                    '.tmp/templates.js'
                ],
                dest: './dist/staffim-auth.js'
            }
        },
        ngtemplates: {
            dist: {
                cwd: 'src/',
                src: ['staffim-auth/**/*.html'],
                dest: '.tmp/templates.js',
                options: {
                    prefix: '/',
                    module: 'staffimAuth'
                }
            }
        },
        clean: {
            working: {
                src: ['./.tmp/']
            }
        }
    });

    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-angular-templates');

    grunt.registerTask('dist', ['clean', 'ngtemplates', 'concat']);
};
