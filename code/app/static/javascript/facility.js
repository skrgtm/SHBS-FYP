$(document).ready(function() {
    var csrf_token = $('meta[name=csrf-token]').attr('content');
    $.ajaxSetup({
      beforeSend: function(xhr, settings) {
        if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
          xhr.setRequestHeader("X-CSRFToken", csrf_token);
        }
      }
    });
  
    $.getJSON('/get_facilities', function(data) {
      var facilitySelect = $('#facility');
      facilitySelect.empty();
      $.each(data, function(index, facility) {
          var option = $('<option></option>').attr('value', facility.id).text(facility.Name);
          facilitySelect.append(option);
      });
  });
  });

$('#facility').on('change', function() {
var facilityName = $(this).val();
$.getJSON('/facility_data/' + facilityName, function(data) {
    $('#Name').val(data.name);
    $('#Capacity').val(data.capacity);
    $('#Start_time').val(data.start_time);
    $('#End_time').val(data.end_time);
});
});
