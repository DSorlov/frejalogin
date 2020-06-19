
const socket = io.connect();

socket.on('connect', () => {
  socket.emit("authRequest", {});
});

socket.on("authResponse", data => {
    
    if (data.status === 'preparing') {
      $('#statusLabel').html('Skapar begäran..');
    } else if (data.status === 'initialized') {
      $('#statusLabel').html('Väntar på servern..');
    } else if (data.status==='pending') {
        switch (data.code) {
            case "pending_notdelivered": {
              $('#statusLabel').html('Levererar begäran till appen..');
              break;
            }
            case "pending_delivered": {
              $('#statusLabel').html('Starta Freja eID appen..');
              break;
            }
            case "pending_user_in_app": {
              $('#statusLabel').html('Authenticera dig i appen..');
              break;
            }
        }
    } else {
        Swal.close();
        $("#SAMLResponse").val(data.ticket);
        $("#RelayState").val(data.state);
        $('#responseForm').attr('action', data.action).submit()
    }
});



