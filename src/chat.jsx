import React, { useState, useEffect } from "react";
import { io } from "socket.io-client";
import "./Chat.css";
import CryptoJS from "crypto-js";
import { useLocation } from "react-router-dom";




function Chat() {
  const { state } = useLocation();
  const username1 = state?.username; // Get the username from the state
  const socket = io("http://localhost:5000", {
    query: {
      username: username1, // Pass the actual username
    },
  });
  
  const [searchTerm, setSearchTerm] = useState("");
  const [userList, setUserList] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedUsers, setSelectedUsers] = useState([]);
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState("");
  const [isGroupChat, setIsGroupChat] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [selectedImage, setSelectedImage] = useState(null);
  const [password, setPassword] = useState("");  // State for storing password input
  const [isPasswordSet, setIsPasswordSet] = useState(false);  // To track if password is set
  const [imagePreview, setImagePreview] = useState(null);

  
  const decryptAESKey = async (encryptedKey, privateKey) => {
  const decoder = new TextDecoder();
  const importedKey = await window.crypto.subtle.importKey(
    "pkcs8",
    Uint8Array.from(atob(privateKey), c => c.charCodeAt(0)),
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["decrypt"]
  );

  // Decrypt the AES key with the private key
  const decryptedKey = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    importedKey,
    Uint8Array.from(atob(encryptedKey), c => c.charCodeAt(0))
  );

  return decoder.decode(decryptedKey); // Return the decrypted AES key as a string
  };

  useEffect(() => {
    // Listen for incoming messages from the server
    socket.on("receive_message", handleReceiveMessage);

    return () => {
      socket.off("receive_message", handleReceiveMessage); // Clean up the event listener
    };
  }, []);

  // Separate function to handle received decrypted messages
  const handleReceiveMessage = async (data) => {
    const { sender, message, aesKey } = data; // Now we also get aesKey
    const receiverUsername = username1; // This should be the selected user who is receiving the message
    const privateKey = localStorage.getItem(`privateKey_${receiverUsername.trim()}`);
    // Get the private key associated with the selected user

    if (!privateKey) {
        console.error("Private key not found for user:", receiverUsername);
        return; // Handle the error accordingly
    }

    // Decrypt the AES key using the receiver's private key
    const decryptedAESKey = await decryptAESKey(aesKey, privateKey);
    console.log("Decrypted AES Key:", decryptedAESKey);

    // Now, use the decrypted AES key to decrypt the message
    const bytes = CryptoJS.AES.decrypt(message, decryptedAESKey);
    const decryptedMessage = bytes.toString(CryptoJS.enc.Utf8);
    console.log("Decrypted message:",decryptedMessage);

    // Append the received decrypted message to the chat history
    setMessages((prevMessages) => [
        ...prevMessages,
        {
            sender,  // Display who sent the message
            text: decryptedMessage,
            type: "text", 
        },
    ]);
  };

  useEffect(() => {
    // Listen for incoming messages from the server
    socket.on("receive_image", handleReceiveImage);

    return () => {
      socket.off("receive_image", handleReceiveImage); // Clean up the event listener
    };
  }, []);

  // Separate function to handle received decrypted messages
  const handleReceiveImage = async (data) => {
    const { sender, message, aesKey } = data; // Now we also get aesKey
    const receiverUsername = username1; // This should be the selected user who is receiving the message
    const privateKey = localStorage.getItem(`privateKey_${receiverUsername.trim()}`);
    // Get the private key associated with the selected user
  
    if (!privateKey) {
        console.error("Private key not found for user:", receiverUsername);
        return; // Handle the error accordingly
    }

    // Decrypt the AES key using the receiver's private key
    const decryptedAESKey = await decryptAESKey(aesKey, privateKey);
    console.log("Decrypted AES Key:", decryptedAESKey);

    const decrypted = CryptoJS.AES.decrypt(message, decryptedAESKey.toString());

    const decryptedBase64 = decrypted.toString(CryptoJS.enc.Utf8);

    console.log("Decrypted base64:",decryptedBase64);
    const imageElement = document.createElement('img');
    imageElement.src = 'data:image/jpeg;base64,' + decryptedBase64;

    // Append the received decrypted message to the chat history
    setMessages((prevMessages) => [
      ...prevMessages,
      {
          sender,
          type: "image",
          imageData: imageElement.src
      }
    ]);
  };

  useEffect(() => {
    // Listen for incoming messages from the server
    socket.on("receive_group_message", handleReceiveGroupMessage);

    return () => {
      socket.off("receive_group_message", handleReceiveGroupMessage); // Clean up the event listener
    };
  }, []);

  // Separate function to handle received decrypted messages
  const handleReceiveGroupMessage = async (data) => {
    const { sender, message, aesKey, group } = data; // Now we also get aesKey
    const receiverUsername = username1; // This should be the selected user who is receiving the message
    const privateKey = localStorage.getItem(`privateKey_${receiverUsername.trim()}`);
    // Get the private key associated with the selected user

    if (!privateKey) {
        console.error("Private key not found for user:", receiverUsername);
        return; // Handle the error accordingly
    }

    // Decrypt the AES key using the receiver's private key
    const decryptedAESKey = await decryptAESKey(aesKey, privateKey);
    console.log("Decrypted AES Key:", decryptedAESKey);

    // Now, use the decrypted AES key to decrypt the message
    const bytes = CryptoJS.AES.decrypt(message, decryptedAESKey);
    const decryptedMessage = bytes.toString(CryptoJS.enc.Utf8);
    console.log("Decrypted message:",decryptedMessage);

    // Append the received decrypted message to the chat history
    setMessages((prevMessages) => [
        ...prevMessages,
        {
            sender,  // Display who sent the message
            type: "text",
            text: decryptedMessage,
            group,  // The actual decrypted message text
        },
    ]);
  };

  useEffect(() => {
    // Listen for incoming messages from the server
    socket.on("receive_group_image", handleReceiveGroupImage);

    return () => {
      socket.off("receive_group_image", handleReceiveGroupImage); // Clean up the event listener
    };
  }, []);

  // Separate function to handle received decrypted messages
  const handleReceiveGroupImage = async (data) => {
    const { sender, message, aesKey, group } = data; // Now we also get aesKey
    const receiverUsername = username1; // This should be the selected user who is receiving the message
    const privateKey = localStorage.getItem(`privateKey_${receiverUsername.trim()}`);
    // Get the private key associated with the selected user
  
    if (!privateKey) {
        console.error("Private key not found for user:", receiverUsername);
        return; // Handle the error accordingly
    }

    // Decrypt the AES key using the receiver's private key
    const decryptedAESKey = await decryptAESKey(aesKey, privateKey);
    console.log("Decrypted AES Key:", decryptedAESKey);

    const decrypted = CryptoJS.AES.decrypt(message, decryptedAESKey.toString());

    const decryptedBase64 = decrypted.toString(CryptoJS.enc.Utf8);

    console.log("Decrypted base64:",decryptedBase64);
    const imageElement = document.createElement('img');
    imageElement.src = 'data:image/jpeg;base64,' + decryptedBase64;

    // Append the received decrypted message to the chat history
    setMessages((prevMessages) => [
      ...prevMessages,
      {
          sender,
          type: "image",
          imageData: imageElement.src,
          group
      }
    ]);
  };

  const handleToggleGroupChat = () => {
    setIsGroupChat(!isGroupChat);
    setSelectedUsers([]); // Reset selected users when switching mode
    setGroupName(""); // Reset the group name
  };

  const handleCreateGroup = () => {
    if (selectedUsers.length > 1) { 
      const groupChatName = groupName || `Group Chat (${selectedUsers.join(", ")})`;
      setSelectedUser(groupChatName);
      setMessages([]); // Reset messages for the new group chat
      socket.emit("create_group", { groupName: groupChatName, members: selectedUsers });
    }
  };

  const handleSearch = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`http://localhost:5000/users?search=${searchTerm}&current_user=${username1}`);
      const data = await response.json();
      setUserList(data);
    } catch (error) {
      console.error("Error fetching users and groups:", error);
    }
  };
  

  
  const handleSelectUser = async (username) => {
    if (isGroupChat) {
      // Check if the user is already in the selectedUsers array
      if (selectedUsers.includes(username)) {
        // User is already selected, remove them
        setSelectedUsers(selectedUsers.filter((user) => user !== username));
    } else {
        // User is not selected, add them
        setSelectedUsers([...selectedUsers, username]);
    }
    }
    
    else if (username.includes('(Group)')) {
        setSelectedGroup(username.replace(' (Group)', ''));
        setSelectedUser(null);
        setMessages([]);

        
        try {
          const response = await fetch(`http://localhost:5000/group_chat_history?group_name=${selectedGroup}`);

          const data = await response.json();
    
          console.log("Fetched chat history:", data);
          if (!Array.isArray(data)) {
            throw new TypeError("Data fetched is not an array");
          }
    
          const decryptedMessages = await Promise.all(data.map(async (msg) => {
            const { sender, message, aesKey, type } = msg;
            
            // Log the AES key being used
            console.log("AES Key for decryption:", aesKey);
    
            
            const privateKey = localStorage.getItem(`privateKey_${username1.trim()}`);
            console.log("Private key:", privateKey);
            if (!privateKey) {
              console.error("Private key not found for user:", username1);
              return null; // Skip if private key is not found
            }
    
            try {
              // Decrypt the AES key with the correct private key
              const decryptedAESKey = await decryptAESKey(aesKey, privateKey);
              console.log("Decrypted AES Key:", decryptedAESKey);
              
              if(type == 'text')
              {
              // Decrypt the message using the decrypted AES key
              const bytes = CryptoJS.AES.decrypt(message, decryptedAESKey);
              const decryptedMessage = bytes.toString(CryptoJS.enc.Utf8);
    
              return {
                sender,
                text: decryptedMessage,
                type: "text"
              };
            }
            else if(type == 'image')
            {
              const decrypted = CryptoJS.AES.decrypt(message, decryptedAESKey.toString());

              const decryptedBase64 = decrypted.toString(CryptoJS.enc.Utf8);

              console.log("Decrypted base64:",decryptedBase64);
              const imageElement = document.createElement('img');
              imageElement.src = 'data:image/jpeg;base64,' + decryptedBase64;

              return{
                sender,
                type: "image",
                imageData: imageElement.src
             }
            }
            } catch (decryptionError) {
              console.error("Error during decryption for message:", decryptionError);
              return null; // Skip this message on decryption failure
            }
          }));
    
          // Filter out any null values and update the messages
          setMessages(decryptedMessages.filter(Boolean));
    
        } catch (error) {
          console.error("Error fetching group chat history:", error);
        }
         // Clear individual user selection
    } 
    else {
      setSelectedUser(username);
      setMessages([]);
  
      // Fetch the chat history for the selected user
      try {
        const response = await fetch(`http://localhost:5000/chat_history?username=${username1}&other_user=${username}`);
        const data = await response.json();
  
        console.log("Fetched chat history:", data);
        if (!Array.isArray(data)) {
          throw new TypeError("Data fetched is not an array");
        }
  
        const decryptedMessages = await Promise.all(data.map(async (msg) => {
          const { sender, message, aesKey, type } = msg;
          
          // Log the AES key being used
          console.log("AES Key for decryption:", aesKey);
  
          
          const privateKey = localStorage.getItem(`privateKey_${username1.trim()}`);
          console.log("Private key:", privateKey);
          if (!privateKey) {
            console.error("Private key not found for user:", username1);
            return null; // Skip if private key is not found
          }
  
          try {
            // Decrypt the AES key with the correct private key
            const decryptedAESKey = await decryptAESKey(aesKey, privateKey);
            console.log("Decrypted AES Key:", decryptedAESKey);
    
            if(type == 'text')
            {
            // Decrypt the message using the decrypted AES key
            const bytes = CryptoJS.AES.decrypt(message, decryptedAESKey);
            const decryptedMessage = bytes.toString(CryptoJS.enc.Utf8);
  
            return {
              sender,
              text: decryptedMessage,
              type: "text"
            };
          }
          else if(type == 'image')
          {
            const decrypted = CryptoJS.AES.decrypt(message, decryptedAESKey.toString());

            const decryptedBase64 = decrypted.toString(CryptoJS.enc.Utf8);

            console.log("Decrypted base64:",decryptedBase64);
            const imageElement = document.createElement('img');
            imageElement.src = 'data:image/jpeg;base64,' + decryptedBase64;

            return{
              sender,
              type: "image",
              imageData: imageElement.src
            }
          }
          } catch (decryptionError) {
            console.error("Error during decryption for message:", decryptionError);
            return null; // Skip this message on decryption failure
          }
        }));
  
        // Filter out any null values and update the messages
        setMessages(decryptedMessages.filter(Boolean));
  
      } catch (error) {
        console.error("Error fetching chat history:", error);
      }
    }
  };
  
  
  


 // Function to fetch the public key for the selected user
  const fetchReceiverPublicKey = async (username) => {
    const response = await fetch(`http://localhost:5000/getPublicKey/${username}`);
    const data = await response.json();
    return data.publicKey; // Adjust based on how your backend returns the key
  };

  // Function to encrypt the AES key using the receiver's public key
  const encryptAESKey = async (aesKey, publicKey) => {
    const encoder = new TextEncoder();
    const importedPublicKey = await window.crypto.subtle.importKey(
        "spki",
        Uint8Array.from(atob(publicKey), c => c.charCodeAt(0)),
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        false,
        ["encrypt"]
    );

  const encryptedKey = await window.crypto.subtle.encrypt(
      {
          name: "RSA-OAEP"
      },
      importedPublicKey,
      encoder.encode(aesKey)
  );

  return btoa(String.fromCharCode(...new Uint8Array(encryptedKey))); // Return as base64
 };


  const handleSendMessage = async (e) => {
    e.preventDefault();

    // Generate a unique AES key for this message

    if (selectedUser) {
      if (selectedImage) {
        
        const reader = new FileReader();
        reader.readAsDataURL(selectedImage);
        
        reader.onload = async () => {
          try {
            const base64Image = reader.result.split(',')[1]; // Remove the "data:image/jpeg;base64," part
            
            console.log("base64 image:",base64Image);
            // Generate a random AES key for encrypting the image
            const aesKey = CryptoJS.lib.WordArray.random(16); // 128-bit key
            const encryptedImage = CryptoJS.AES.encrypt(base64Image, aesKey.toString()).toString();

            console.log("AES Key generated:", aesKey.toString());
            console.log("Encrypted image:", encryptedImage);

            const receiverPublicKey = await fetchReceiverPublicKey(selectedUser);
            const senderPublicKey = await fetchReceiverPublicKey(username1); // Fetch the sender's public key

            // Encrypt the AES key using the selected user's public key
            const encryptedAESKey_sender = await encryptAESKey(aesKey, senderPublicKey);
            const encryptedAESKey_receiver = await encryptAESKey(aesKey, receiverPublicKey);

            // Send the encrypted image and AES key to the server via WebSocket
            console.log("Sending image...");
            socket.emit("send_image", {
                sender: username1,
                receiver: selectedUser,
                message: encryptedImage,
                aesKey: encryptedAESKey_sender,
                raesKey: encryptedAESKey_receiver,
                type: "image",
            });
            
            console.log("Image sent successfully!");
            // Clear the selected image after sending
            
            setMessages((prevMessages) => [...prevMessages, { sender: username1, imageData: selectedImage, type: "image" }]);
            setSelectedImage(null);

          }
          catch (error) {
            console.error("Error processing image:", error);
          }
        };
    }

   else
   {
    if (inputMessage.trim() === "") return;
    const aesKey = CryptoJS.lib.WordArray.random(16).toString(); // Example: Generate a random AES key
    const encryptedMessage = CryptoJS.AES.encrypt(inputMessage, aesKey).toString();

    // Get the selected user's public key
    const receiverPublicKey = await fetchReceiverPublicKey(selectedUser);
    
    const senderPublicKey = await fetchReceiverPublicKey(username1);// Implement this function to fetch the public key

    // Encrypt the AES key using the selected user's public key
    const encryptedAESKey_sender = await encryptAESKey(aesKey, senderPublicKey);

    const encryptedAESKey_receiver = await encryptAESKey(aesKey, receiverPublicKey);

    const messageData = {
        sender: username1, // Replace this with the actual sender's username
        receiver: selectedUser, // The selected user who will receive the message
        message: encryptedMessage,
        key: aesKey,
        EaesKey: encryptedAESKey_sender,
        Raeskey: encryptedAESKey_receiver, 
        type: "text",
    };

    setMessages((prevMessages) => [...prevMessages, { sender: messageData.sender, text: inputMessage, type: "text" }]);
    socket.emit("send_message", messageData);
    setInputMessage("");
   }
  }
  else if (selectedGroup) 
   {
    if (selectedImage) {
      const response = await fetch(`http://localhost:5000/groups/members?groupName=${selectedGroup}`);
      const { members } = await response.json();
        
      const reader = new FileReader();
      reader.readAsDataURL(selectedImage);
      
      reader.onload = async () => {
        try {
          const base64Image = reader.result.split(',')[1]; // Remove the "data:image/jpeg;base64," part
          
          console.log("base64 image:",base64Image);
          // Generate a random AES key for encrypting the image
          const aesKey = CryptoJS.lib.WordArray.random(16); // 128-bit key
          const encryptedImage = CryptoJS.AES.encrypt(base64Image, aesKey.toString()).toString();

          console.log("AES Key generated:", aesKey.toString());
          console.log("Encrypted image:", encryptedImage);
          
          for (const member of members) {
              const receiverPublicKey = await fetchReceiverPublicKey(member);
              const senderPublicKey = await fetchReceiverPublicKey(username1); // Fetch the sender's public key

              // Encrypt the AES key using the selected user's public key
              const encryptedAESKey_sender = await encryptAESKey(aesKey, senderPublicKey);
              const encryptedAESKey_receiver = await encryptAESKey(aesKey, receiverPublicKey);

              // Send the encrypted image and AES key to the server via WebSocket
              console.log("Sending image...");
              socket.emit("send_group_image", {
                  sender: username1,
                  receiver: member,
                  message: encryptedImage,
                  key: aesKey,
                  aesKey: encryptedAESKey_sender,
                  raesKey: encryptedAESKey_receiver,
                  group_name: selectedGroup,
                  type: "image",
              });
              
              
              // Clear the selected image after sending
          }
          setMessages((prevMessages) => [...prevMessages, { sender: username1, imageData: selectedImage, type: "image" }]);
          setSelectedImage(null);

        }
        catch (error) {
          console.error("Error processing image:", error);
        }
      };
  }
  else{
    try {
      // Fetch all group members
        const response = await fetch(`http://localhost:5000/groups/members?groupName=${selectedGroup}`);
        const { members } = await response.json();
        
        const aesKey = CryptoJS.lib.WordArray.random(16).toString(); // Example: Generate a random AES key
        const encryptedMessage = CryptoJS.AES.encrypt(inputMessage, aesKey).toString();
        // For each member, encrypt the AES key with their public key and send the message
        for (const member of members) {
            const receiverPublicKey = await fetchReceiverPublicKey(member);

            const senderPublicKey = await fetchReceiverPublicKey(username1);

            // Encrypt the AES key with the member's public key
            const encryptedAESKey_sender = await encryptAESKey(aesKey, senderPublicKey);

            const encryptedAESKey_receiver = await encryptAESKey(aesKey, receiverPublicKey);

            // Prepare the message data for this member
            const messageData = {
                sender: username1, // Replace this with the actual sender's username
                receiver: member,  // The specific group member who will receive the message
                message: encryptedMessage,
                key: aesKey,
                EaesKey: encryptedAESKey_sender,
                Raeskey: encryptedAESKey_receiver,
                group_name: selectedGroup,
                type: "text",
            };
            
            // Send the message to the server for each group member
            socket.emit("send_group_message", messageData);

        }
        
        setInputMessage("");
       } catch (error) {
      console.error("Error sending group message:", error);
      }
    }
   }
  };

  

  const handleImageSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
        setSelectedImage(file);
        setImagePreview(URL.createObjectURL(file));
            const reader = new FileReader();
            reader.onload = (e) => {
              console.log("Image URL:", e.target.result); // Or update a state to show preview
            };
            reader.readAsDataURL(file);
            URL.revokeObjectURL(imagePreview); 
          }
         
        
        };



const [isModalOpen, setIsModalOpen] = useState(false);

const openModal = (user) => {
  setSelectedUser(user); // Set the selected user
  setIsModalOpen(true); // Open the modal
  checkPassword(user); // Check if password is already set for this user
};

const closeModal = () => {
  setIsModalOpen(false);
  setPassword(""); // Clear password input on close
};


const checkPassword = async (user) => {
  // Fetch from backend to check if password is set for the selected user
    try{
      const response = await fetch(`http://localhost:5000/check_password?logged_in_user=${username1}&selected_user=${user}`);
      const data = await response.json();
      if (data.password) {
        setIsPasswordSet(true);  // If password exists, set the state to true
      } else {
        setIsPasswordSet(false);  // If no password, allow the user to set one
      }
    }
    catch (error) {
      console.error("Error checking password:", error);
      setIsPasswordSet(false); // Fallback in case of error
    }
  };
  

const handleSetPassword = async () => {
  if (password.length < 6) {
    alert("Password must be at least 6 characters long.");
    return;
  }

  // Send password to backend for hashing and storing in chat_passwords table
  const response = await fetch("http://localhost:5000/set_password", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      logged_in_user: username1,
      selected_user: selectedUser,
      password: password,
    }),
  });

  if (response.ok) {
    alert("Password set successfully!");
    setIsPasswordSet(true);
  } else {
    alert("Error setting password. Try again.");
  }
  setPassword(""); // Clear the password field
};


 // Handle password verification (for unlocking chat)
 const handleVerifyPassword = async () => {
  const response = await fetch("http://localhost:5000/verify_password", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      logged_in_user: username1,
      selected_user: selectedUser,
      password: password,
    }),
  });

  const data = await response.json();

  if (data.isValid) {
    alert("Password verified. Chat unlocked!");
    setIsModalOpen(false);
    closeModal();
     // Close modal after successful verification
     handleSelectUser(selectedUser);
  } else {
    alert("Incorrect password. Try again.");
  }
  setPassword(""); // Clear the password field
};


  return (
    <div className="chat-container">
      <div className="sidebar">
        <h2>Chats</h2>
        <form onSubmit={handleSearch} className="search-form">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search or start a new chat"
            className="search-input"
          />
        </form>

        <div className="user-list">
            {userList.length === 0 ? (
              <p>No users or groups found</p>
            ) : (
              userList.map((user, index) => (
                <div
                  key={index}
                  className={`user-item ${
                    isGroupChat
                      ? selectedUsers.includes(user) ? "selected-user" : ""
                      : selectedUser === user ? "selected-user" : ""
                  }`}
                  onClick={() => openModal(user)} 
                >
                  {user}
                </div>
              ))
            )}
          </div>
 
          {isModalOpen && (
         <div className="modal">
          <div className="modal-content">


            <h2>{isPasswordSet ? "Enter your password" : "Set a password"}</h2>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
            />
          </div>
          {isPasswordSet ? (
                <button className="verify-password-btn" onClick={handleVerifyPassword}>Unlock Chat</button>
              ) : (
                <button  className="set-password-btn" onClick={handleSetPassword}>Set Password</button>
              )}
        </div>
      )}
      
        {isGroupChat && (
          <>
            <input
              type="text"
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              placeholder="Group Name (optional)"
              className="group-name-input"
            />
            <button className="create-group-button" onClick={handleCreateGroup} disabled={selectedUsers.length < 2}>
              Create Group
            </button>
          </>
        )}
        <button className="toggle-group-chat" onClick={handleToggleGroupChat}>
          {isGroupChat ? "Cancel Group Chat" : "Create Group Chat"}
        </button>
      </div>

    <div className="chat-window">
    {(selectedUser || selectedGroup) ? (
    <>
      <div className="chat-header">
        <h2>{selectedUser ? selectedUser : `${selectedGroup} (Group)`}</h2>
      </div>

      <div className="chat-window-content">
        {messages.length === 0 ? (
          <p className="no-messages">No messages yet</p>
        ) : (
          messages.map((msg, index) => (
            <div key={index} className={`message ${msg.sender === username1 ? "sent" : "received"}`}>
              <strong>{msg.sender}: </strong>
              
              {msg.type === "text" ? (
                // Display text message
                <p>{msg.text}</p>
              ) : msg.type === "image" ? (
                // Display image message
                <img src={msg.imageData} alt="Sent image" className="sent-image" />
              ) : null}
            </div>
          ))
        )}
      </div>

      <form className="chat-input" onSubmit={handleSendMessage}>
        <input
          type="text"
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          placeholder="Type a message..."
          className="input-message"
        />
        <input
          type="file"
          accept="image/*"
          onChange={handleImageSelect}
          className="file-input"
        />
        {imagePreview && (
        <div className="image-preview">
          <img src={imagePreview} alt="Image preview" style={{ maxWidth: "200px", maxHeight: "200px" }} />
        </div>
      )}
        <button type="submit" className="send-button">Send</button>
      </form>
     </>
     ) : (
        <p className="welcome-message">Select a user or create a group to start chatting!</p>
     )}
   </div>

 
    </div>
  );
}

export default Chat;


