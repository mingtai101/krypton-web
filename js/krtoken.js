//window.supercop = supercop_wasm ? supercop_wasm: null;
window.supercop = null;
window.scrypt = null;
window.SCRYPT_PARAMS = {
    N: Math.pow(2, 17),
    R: 8,
    P: 1,
    OutputLength: 32
};

function showNotify(level, title, message) {
  $.notify({
    title: title,
    message: message,
  },{
    element: 'body',
    type: level,
    placement: {
      from: "bottom",
      align: "left"
    },
    offset: {
      x: 0,
      y: 80
    }
  });
}

function showErrorNotifyWithTitle(title, message) {
  showNotify('danger', title, message);
}

function showWarningNotifyWithTitle(title, message) {
  showNotify('warning', title, message);
}

function showInfoNotifyWithTitle(title, message) {
  showNotify('info', title, message);
}


function showErrorNotify(message) {
  showNotify('danger', null, message);
}

function showWarningNotify(message) {
  showNotify('warning', null, message);
}

function showInfoNotify(message) {
  showNotify('info', null, message);
}

function showError(error) {
  showErrorNotify(error.msg);
}

var theOpendToken = [];
function itemOnMouseOver(item) {
  $(item).find('a:first').css({display: 'inline'})

}
function itemOnMouseOut(item) {
  $(item).find('a:first').css({display: 'none'})
}
function showItemList(token) {
  theOpendToken = token;
  var shareList = $('#kr-item-list');
  shareList.empty();
  for(var i=0; i<token.length; i++) {
    //  li: onclick="showTokenItem(' + i + ')" onmouseover="itemOnMouseOver(this)" onmouseout="itemOnMouseOut(this);"
    // <a href="#" style="display: none; padding: 0 0 0 10px;" onclick="removeItemFromToken(' + i + ');  event.stopPropagation(); return true;"> X </a>
    shareList.append('<li class="list-group-item" onclick="showTokenItem(' + i + ')" >' + token[i].subject + '</li>');
  }
  $('#kr-item-list-container').css({display: 'inline'});
  // $('#share-list').css({display: 'inline'})
}
function shareToString(share) {
  if (!share.encoding) {
    return share.value;
  }

  if (share.encoding.toLowerCase() == 'utf-8') {
    /*
    var bytes = base32.decode.asBytes(share.value);
    if (!bytes || bytes.length == 0)
      return share.value;
    var words = byteArrayToWordArray(bytes);
    return CryptoJS.enc.Utf8.stringify(words);
    */
    return share.value;
  }
  return share.value;
}

function showTokenItem(idx) {
  var share = theOpendToken[idx];
  $('#kr-item-details').text(shareToString(share));
  $('#kr-item-title').text(share.subject);
  $('#kr-item-footer').html('&nbsp;&nbsp;&nbsp;&nbsp;<button class="btn btn-danger" id="delete-button" onclick="removeItemFromToken(' + idx + ');">Delete Entry</button>&nbsp;&nbsp;&nbsp;&nbsp;\n' +
    '          <div id="delete-indicator" class="spinner-border" role="status" style="color: #00aaff; display: none;">\n' +
    '            <span class="sr-only">Deleting...</span>\n' +
    '          </div>');
  $('#kr-item-details-container').css({display: 'inline'});
}

function removeItemFromToken(idx) {
  var res = confirm("Do you want to delete the content under this label?");
  if (!res) {
    return;
  }
  $('#delete-button').attr('disabled', 'disabled');
  $('#delete-indicator').css({display: 'inline-block'});
  var share = theOpendToken[idx];
  restClient.removeShare(share.subject, function(result) {
    $('#delete-button').removeAttr('disabled');
    $('#delete-indicator').css({display: 'none'});
    if(result.code != 0) {
      showError(result);
      return;
    }
    theOpendToken.splice(idx, 1)
    var newToken = theOpendToken;
    showItemList(newToken);
    document.getElementById('kr-item-details-container').style.display = 'none';
    // $('#kr-item-list').find('li').eq(i).remove();
  });
}
function doOpenKryptonToken() {
  if (restClient.getSalt() == defaultTokenTypePrefix) {
    showErrorNotify("Entropy Salt could not be empty.");
    $('#open-button').removeAttr('disabled');
    return;
  };
  if (!restClient.getPassphrase() || restClient.getPassphrase().length < 6) {
    showErrorNotify("Passphrase could not be empty.");
    $('#open-button').removeAttr('disabled');
    return;
  }
    /*
    var entropySalt = $('#entropy-salt-tf').val();
    var passphrase = $('#passphrase-tf').val();
    var result = derivateFileNameAndEncryptionKey(entropySalt, passphrase);
    getKryptonToken(result, function(result) {
        if (result.code != 0) {
            showError(error);
            return;
        }
        window.token = result.data;
        showItemList(result.data);
    })
    document.getElementById('kr-item-list').style.display = 'inline';
    */

    // restClient.getShares(function(result) {
    //     console.log(result);
    // });
  $('#open-indicator').css({display: 'inline-block'});
  restClient.getShares(function(result) {
    $('#open-button').removeAttr('disabled');
    console.log(result);
    $('#open-indicator').css({display: 'none'});
    if(result.code != 0) {
      if (result.code == -1) {
        /*
        var res = confirm("Krypton Token not found. Do you want to create a new one?");
        if (res) {
          theOpendToken = [];
          showEditor();
          return;
        }*/
        showErrorNotify("Krypton Token does not exist.")
        return;
      }
      showError(result);
      return;
    }
    gotoGuideScreen();
    showItemList(result.data);
  });
}

function doCreateKryptonToken() {

  if (restClient.getSalt() == defaultTokenTypePrefix) {
    showErrorNotify("Entropy Salt could not be empty.");
    $('#open-button').removeAttr('disabled');
    return;
  };
  if (!restClient.getPassphrase() || restClient.getPassphrase().length < 6) {
    showErrorNotify("Passphrase too weak.");
    $('#open-button').removeAttr('disabled');
    return;
  }

  $('#open-indicator').css({display: 'inline-block'});
  restClient.getShares(function(result) {
    console.log(result);
    $('#open-button').removeAttr('disabled');
    $('#open-indicator').css({display: 'none'});
    if(result.code != 0) {
      if (result.code == -1) {
        theOpendToken = [];
        showEditor();
        gotoGuideScreen();
        return;
      }
      showError(result);
      return;
    }

    showErrorNotify("Krypton Token already exists.")

    /*
    var res = confirm("Krypton Token already exists. Do you want to open it?");
    if (res) {
      showItemList(result.data);
    }
    */
  });
}


var createOrOpenKryptonTokenFn = function() {};
function scryptOnReady(scrypt) {
    window.scrypt = scrypt;
    createOrOpenKryptonTokenFn();
}

function supercopOnReady() {
  $('#page-load-indicator').css({display: 'none'});
}

function documentOnReady() {
  initial_supercop_wapper(function() {
    window.supercop = supercop_wasm ? supercop_wasm: null;
    supercop.ready(supercopOnReady);
  })
}

$(document).ready(documentOnReady);


function openClicked() {
    $('#open-button').attr('disabled', 'disabled');
    if (window.scrypt) {
      doOpenKryptonToken()
    } else {
      createOrOpenKryptonTokenFn = doOpenKryptonToken;
      scrypt_module_factory(scryptOnReady, {requested_total_memory: 33554432 * 10});
    }
}

function createClicked() {
  $('#open-button').attr('disabled', 'disabled');
  if (window.scrypt) {
    doCreateKryptonToken()
  } else {
    createOrOpenKryptonTokenFn = doCreateKryptonToken;
    scrypt_module_factory(scryptOnReady, {requested_total_memory: 33554432 * 10});
  }
}

function doSave(shareName, shareValue, covered, cb) {

  $('#save-indicator').css({display: 'inline-block'});
  $('#save-button').attr('disabled', 'disabled');
  restClient.saveShare(shareName, shareValue, false, function(result) {
    $('#save-button').removeAttr('disabled');
    $('#save-indicator').css({display: 'none'});
    if (result.code != 0) {
      if (result.code == -50001) {
        var res = confirm("This label already exists, Do you want to overwrite this label with the new imputs?");
        if (res) {
          cb();
        }
        return;
      }
      showError(result);
      return;
    }

    var success = restClient.updateTokenObject(theOpendToken, shareName, shareValue, true);
    if (success) {
      var newToken = theOpendToken;
      hideEditor();
      showItemList(newToken);
    }
  });
}

function saveClicked() {
  var shareName = $('#item-subject-tf').val();
  var shareValue = $('#item-value-tf').val();
  if (!shareName || shareName.length == 0) {
    showErrorNotify("The label must not be empty.");
    return;
  }
  doSave(shareName, shareValue, false, function() {
    doSave(shareName, shareValue, true, function() {})
  });

}
