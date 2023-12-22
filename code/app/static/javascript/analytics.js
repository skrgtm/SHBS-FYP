google.charts.load("current", { packages: ["corechart"] });
$("#member").on("click", function (data) {
  $.getJSON("/analyzemember", function (data) {
    // Define the data for the chart
    var displaydata = google.visualization.arrayToDataTable([
      ["Membership", "Count"],
      ["Members", data.members],
      ["Non-Members", data.nonmembers],
    ]);

    // Define the options for the chart
    var options = {
      title: "Membership Analysis",
      pieHole: 1,
      legend: { position: "top" },
      pieSliceText: "value-and-percentage",
      colors: ["#007bff", "#28a745"],
      is3D: true,
      animation: {
        startup: true,
        duration: 1000,
        easing: "out",
      },
      width: 400,
      height: 400,
    };
    // Remove any existing chart from the container
    $("#memberChart").empty();

    // Create the chart and append it to the container
    var chart = new google.visualization.PieChart(
      document.getElementById("memberChart")
    );
    chart.draw(displaydata, options);
  });
});

$("#bookings").on("click", function (data) {
  $.getJSON("/analyzebookings", function (data) {
    document.getElementById("total-bookings").innerHTML = data.totalbookings;
    document.getElementById("total-booking-size").innerHTML = data.totalsize;
    document.getElementById("average-size").innerHTML = data.avgsize;

    $("#bookings").after($("#bookingtable"));
    document.getElementById("bookingtable").style.display = "table";
  });
});

$("#facility").on("click", function () {
  var filter_type = $("#my-select").val();
  $("#facilitytable thead").empty();
  $("#facilitytable tbody").empty();
  if (filter_type == "Booking") {
    $("#facilitytable thead").append(
      '<tr class="text-white"><th class="text-white">Ranking</th><th class="text-white">Facility Name</th><th class="text-white">Number of Bookings</th></tr>'
    );
    $.getJSON("/rankfacilities/" + filter_type, function (data) {
      $.each(data, function (index, facility) {
        var row =
          '<tr class="text-white"><td>' +
          facility.ranking +
          "</td><td>" +
          facility.facility_name +
          "</td><td>" +
          facility.booking_count +
          "</td></tr>";
        $("#facilitytable tbody").append(row);
      });
      $("#facility").after(
        $("#facilitytable").css("padding-bottom", "20px").show()
      );

      $("#facilitytable").show();
    });
  } else if (filter_type == "Utilization") {
    $("#facilitytable thead").append(
      '<tr><th class="text-white" >Ranking</th><th class="text-white">Facility Name</th><th class="text-white">Utilization</th></tr>'
    );
    $.getJSON("/rankfacilities/" + filter_type, function (data) {
      $.each(data, function (index, facility) {
        var row =
          '<tr class="text-white"><td>' +
          facility.ranking +
          "</td><td>" +
          facility.facility_name +
          "</td><td>" +
          facility.booking_count +
          "%" +
          "</td></tr>";
        $("#facilitytable tbody").append(row);
      });
      $("#facility").after($("#facilitytable"));
      $("#facilitytable").show();
    });
  }
});

$("#revenue").on("click", function (data) {
  var month_value = $("#month-select").val();
  var year_value = $("#year-select").val();
  $.getJSON(
    "/getrevenues/" + month_value + "/" + year_value,
    function (json_data) {
      var data_table = new google.visualization.DataTable();
      data_table.addColumn("string", "Facility");
      data_table.addColumn("number", "Total Revenue");

      $.each(json_data, function (facility_name, facility_data) {
        var total_revenue = 0;
        $.each(facility_data, function (index, month_data) {
          total_revenue += month_data.total_revenue;
          data_table.addRow([facility_name, total_revenue]);
        });
      });
      var options = {
        title: "Monthly Revenue by Facility",
        legend: { position: "none" },
        chartArea: { width: "50%" },
        hAxis: {
          title: "Facility",
          minValue: 0,
        },
        vAxis: {
          title: "Total Revenue",
        },
        annotations: {
          alwaysOutside: true,
          textStyle: {
            fontSize: 12,
            color: "#000",
            auraColor: "none",
          },
        },
      };

      $("#revenueChart").empty();
      var chart = new google.visualization.ColumnChart(
        document.getElementById("revenueChart")
      );
      chart.draw(data_table, options);
    }
  );
});

$("#facilityanalytics").click(function () {
  // Get the selected usagetype and week number
  var usagetype = $("#facilityfilter").val();
  var week = parseInt($("#weekSelector1").val());

  // Send an AJAX request to the facilitywiseinfo route
  $.getJSON("/facilitywiseinfo/" + usagetype + "/" + week, function (data) {
    // Create a data table using the response data
    var dataTable = new google.visualization.DataTable();
    dataTable.addColumn("string", "Facility");
    dataTable.addColumn("number", usagetype);
    $.each(data, function (index, item) {
      dataTable.addRow([item.facility_name, item.data]);
    });
    console.log(data);

    // Create a column chart using the data table
    $("#facilityinfographic").empty();
    var chart = new google.visualization.ColumnChart(
      document.getElementById("facilityinfographic")
    );
    chart.draw(dataTable, {
      title: "Facility " + usagetype + " for Week " + week,
      height: 400,
      legend: { position: "none" },
    });
  });
});

$("#activityanalytics").click(function () {
  // Get the selected usagetype and week number
  var usagetype = $("#activityfilter").val();
  var week = $("#weekSelector2").val();

  // Send an AJAX request to the activitywiseinfo route
  $.getJSON(
    "/activitywiseinfo/" + usagetype + "/" + parseInt(week),
    function (data) {
      // Create a data table using the response data
      var dataTable = new google.visualization.DataTable();
      dataTable.addColumn("string", "Activity");
      dataTable.addColumn("number", usagetype);
      $.each(data, function (index, item) {
        dataTable.addRow([item.activity_name, item.data]);
      });
      console.log(data);

      // Create a column chart using the data table
      $("#activityinfographic").empty();
      var chart = new google.visualization.ColumnChart(
        document.getElementById("activityinfographic")
      );
      chart.draw(dataTable, {
        title: "Activity " + usagetype + " for Week " + week,
        height: 400,
        legend: { position: "none" },
      });
    }
  );
});

$(document).ready(function () {
  var csrf_token = $("meta[name=csrf-token]").attr("content");
  $.ajaxSetup({
    beforeSend: function (xhr, settings) {
      if (
        !/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) &&
        !this.crossDomain
      ) {
        xhr.setRequestHeader("X-CSRFToken", csrf_token);
      }
    },
  });
});
