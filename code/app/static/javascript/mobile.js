// initialize FlagKit
FK.init({ theme: 'flat' });

// add flags to options
var options = document.getElementById('country').options;
for (var i = 0; i < options.length; i++) {
  var option = options[i];
  if (option.value) {
    option.innerHTML = FK.countryFlag(option.value) + ' ' + option.innerHTML;
  }
}
