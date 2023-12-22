function cancel_booking(id) {
  var intid = parseInt(id);
  $.ajax({
    url: '/cancel_booking/' + intid,
    type: 'POST',
    success: function(response) {
      location.reload();
    },
    error: function(error) {
      console.log(error);
      location.reload();
    }
  });  
}


$('#Facility_Namez').on('load', function() {
  var facilityName = $(this).val();
  $.getJSON('/facility_data/' + facilityName, function(data) {
    $('#Name').val(data.name);
    $('#Capacity').val(data.capacity);
    $('#Start_time').val(data.start_time);
    $('#End_time').val(data.end_time);
    $('#Amount').val(data.amount);
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

$('#Facility_Namez').on('change', function() {
  var facilityName = $(this).val();
  $.getJSON('/facility_data/' + facilityName, function(data) {
    $('#Name').val(data.name);
    $('#Capacity').val(data.capacity);
    $('#Start_time').val(data.start_time);
    $('#End_time').val(data.end_time);
    $('#Amount').val(data.amount);
  });
});


$('#Activity_Selector').on('change', function() {
  var facilityName = $(this).val();
  $.getJSON('/activity_data/' + facilityName, function(data) {
    $('#New_Activity_Name').val(data.name);
    $('#New_Amount').val(data.amount);
    $('#New_Facility_Name').val(data.facility_id);
  });
});

$("#New_Facility_Name").change(function() {
  var facility_id = parseInt($(this).val());
  $.getJSON("/facility_activities/" + facility_id, function(data) {
      $("#Activity_Selector").empty();  // remove existing options
      $.each(data, function(index, activity) {
          $("#Activity_Selector").append('<option value="' + activity[0] + '">' + activity[1] + '</option>');
      });
  });
});



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
