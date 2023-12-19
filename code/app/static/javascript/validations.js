const passwordInput = document.getElementById('userPassword');
const passwordError = document.getElementById('password-error');
const submit = document.getElementById('submitbtn');

passwordInput.addEventListener('input', validatePassword);

function validatePassword() {
  const password = passwordInput.value;
  let errorMessage = '';

  // Check the length of the password
  if (password.length < 8) {
    errorMessage += 'Password must be at least 8 characters long<br>';

  }

  // Check if the password contains at least one uppercase letter
  if (!/[A-Z]/.test(password)) {
    errorMessage += 'Password must contain at least one uppercase letter<br>';

  }

  // Check if the password contains at least one lowercase letter
  if (!/[a-z]/.test(password)) {
    errorMessage += 'Password must contain at least one lowercase letter<br>';

  }

  // Check if the password contains at least one number
  if (!/\d/.test(password)) {
    errorMessage += 'Password must contain at least one number<br>';

  }

  // Check if the password contains at least one special character
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errorMessage += 'Password must contain at least one special character<br>';

  }

  // Update the UI to show the error messages or clear the error messages if there are none
  if (errorMessage) {
    passwordError.innerHTML = errorMessage;
    submit.disabled = true;
    return false;
  } else {
    passwordError.innerHTML = '';
    submit.disabled = false;
    return true;
  }
}

  

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
