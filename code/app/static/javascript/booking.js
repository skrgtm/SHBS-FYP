function updateDiscount(totalAmount, itemsInCart) {
    let discount = 0;
    if (itemsInCart >= 3) {
        discount = totalAmount * 0.15;
    }

    return Math.round(discount);
}

$('.increase-quantity-btn').on('click', function(event) {
    event.preventDefault();

    const bookingId = $(this).data('booking-id');
    const url = `/increase_quantity/${bookingId}`;

    $.ajax({
        type: 'POST',
        url: url,
        success: (result) => {
            if (result.status === 'success') {
                // Update the relevant DOM elements
                const totalSizeEl = $(this).closest('.list-group-item').find('#total-size');
                const amountEl = $(this).closest('.list-group-item').find('#amount');
                const currencySymbol = '&#163;';
                
                totalSizeEl.html(`Size: ${result.total_size}`);
                amountEl.html(`${currencySymbol} ${result.amount}`);
                // Update the total amount
                let totalAmount = 0;
                $('.amount').each(function() {
                    const amountText = $(this).text().replace('&#163;', '').replace('£', '');
                    totalAmount += parseFloat(amountText);
                });

                $('#total_amount').text(totalAmount);
                const payNowLink = document.getElementById('pay_now_link');
                const newHref = `/order_products?total_amount=${totalAmount}`;
                payNowLink.setAttribute('href', newHref);

                // Update discount and original amount if applicable
                if ($('#original_amount').length) {
                    const itemsInCart = $('.list-group-item:not(:last-child)').length;
                    const newDiscount = updateDiscount(totalAmount, itemsInCart);
                    $('#discount').html(`&#163; ${newDiscount}`);
                    $('#total_amount').html(`&#163; ${totalAmount - newDiscount}`);
                    $('#original_amount').html(`&#163; ${totalAmount}`);
                    const payNowLink = document.getElementById('pay_now_link');
                    const newHref = `/order_products?total_amount=${totalAmount-newDiscount}`;
                    payNowLink.setAttribute('href', newHref);
                }
            } else {
                console.error(result.message);
            }
        },
        error: (error) => {
            console.error(error);
        }
    });
});



$('.decrease-quantity-btn').on('click', function(event) {
    event.preventDefault();

    const bookingId = $(this).data('booking-id');
    const url = `/decrease_quantity/${bookingId}`;

    $.ajax({
        type: 'POST',
        url: url,
        success: (result) => {
            if (result.status === 'success') {
                // Update the relevant DOM elements
                const totalSizeEl = $(this).closest('.list-group-item').find('#total-size');
                const amountEl = $(this).closest('.list-group-item').find('#amount');
                const currencySymbol = '&#163;';
                
                totalSizeEl.html(`Size: ${result.total_size}`);
                amountEl.html(`${currencySymbol} ${result.amount}`);
                // Update the total amount
                let totalAmount = 0;
                $('.amount').each(function() {
                    const amountText = $(this).text().replace('&#163;', '').replace('£', '');
                    totalAmount += parseFloat(amountText);
                });

                $('#total_amount').text(totalAmount);
                const payNowLink = document.getElementById('pay_now_link');
                const newHref = `/order_products?total_amount=${totalAmount}`;
                payNowLink.setAttribute('href', newHref);

                // Update discount and original amount if applicable
                if ($('#original_amount').length) {
                    const itemsInCart = $('.list-group-item:not(:last-child)').length;
                    const newDiscount = updateDiscount(totalAmount, itemsInCart);
                    $('#discount').html(`&#163; ${newDiscount}`);
                    $('#total_amount').html(`&#163; ${totalAmount - newDiscount}`);
                    $('#original_amount').html(`&#163; ${totalAmount}`);
                    const payNowLink = document.getElementById('pay_now_link');
                    const newHref = `/order_products?total_amount=${totalAmount-newDiscount}`;
                    payNowLink.setAttribute('href', newHref);
                }
            } else {
                console.error(result.message);
            }
        },
        error: (error) => {
            console.error(error);
        }
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
  });