/*
 * View model for OctoPrint-Mglcd
 *
 * Author: MG|Josh
 * License: AGPLv3
 */
$(function() {
    function MglcdViewModel(parameters) {
        var self = this;

        // assign the injected parameters, e.g.:
        // self.loginStateViewModel = parameters[0];
        // self.settingsViewModel = parameters[1];

        // TODO: Implement your plugin's view model here.

        self.flashFirmware = function() {
            var url = OctoPrint.getSimpleApiUrl("mglcd");
            OctoPrint.issueCommand(url, "flashNextionFirmware")
                .done(function(response) {
                    console.log(response);
            });
        };



    }

    // view model class, parameters for constructor, container to bind to
    OCTOPRINT_VIEWMODELS.push([
        MglcdViewModel,

        // e.g. loginStateViewModel, settingsViewModel, ...
        [ /* "loginStateViewModel", "settingsViewModel" */ ],

        // e.g. #settings_plugin_mglcd, #tab_plugin_mglcd, ...
        ["#mglcdSettings"]
    ]);
});
