$(document).ready(function() {
    var csrf_token = $('meta[name=csrf-token]').attr('content');
    $.ajaxSetup({
      beforeSend: function(xhr, settings) {
        if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
          xhr.setRequestHeader("X-CSRFToken", csrf_token);
        }
      }
    });
  });


  $("#New_Facility_Name").change(function() {
    var facility_id = parseInt($(this).val());
    $.getJSON("/facility_activities/" + facility_id, function(data) {
        $("#activity_select").empty();  // remove existing options
        $.each(data, function(index, activity) {
            $("#activity_select").append('<option value="' + activity[0] + '">' + activity[1] + '</option>');
        });
    });
  });


  $('#activity_select').on('change', function() {
    var facilityName = $(this).val();
    $.getJSON('/activity_data/' + facilityName, function(data) {
      $('#activity_name').val(data.name);
      $('#amount').val(data.amount);
    });
  });
  