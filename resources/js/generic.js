
const socket = io.connect();

socket.on('connect', () => {
  socket.emit("authRequest", {});
});

socket.on("authResponse", data => {
    
    if (data.status === 'preparing') {
      Swal.fire({
        imageUrl: "/resources/img/ajax-loader.gif",
        title: "Skapar begräran..",
        heightAuto: false,
        showConfirmButton: false,
        showCancelButton: false
      });
    } else if (data.status === 'initialized') {
        Swal.update({
          title: "Väntar på servern.."
        });          
    } else if (data.status==='pending') {
        switch (data.code) {
            case "pending_notdelivered": {
              Swal.update({
                title: "Levererar begäran till appen.."
              });
            }
            case "pending_delivered": {
              Swal.update({
                title: "Starta Freja eID appen.."
              });
              break;
            }
            case "pending_user_in_app": {
              Swal.update({
                title: "Authenticera dig i appen.."
              });
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



