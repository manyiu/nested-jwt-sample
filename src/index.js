const jose = require("node-jose");
const fs = require("fs");

function parsePayload(token) {
  var base64 = token.replace(/-/g, "+").replace(/_/g, "/");
  var jsonPayload = decodeURIComponent(
    atob(base64)
      .split("")
      .map(function (c) {
        return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
      })
      .join("")
  );

  return JSON.parse(jsonPayload);
}

const main = async () => {
  try {
    const keystore = jose.JWK.createKeyStore();

    const privatepem = fs.readFileSync("./keys/example.key", "utf8");
    const privatekey = await keystore.add(privatepem, "pem");

    const publicpem = fs.readFileSync("./keys/example.crt", "utf8");
    const publickey = await keystore.add(publicpem, "pem");

    const symmetrickey = await keystore.generate("oct", 256);
    console.log("########## KEY ##########");
    console.log(keystore.toJSON(true));
    console.log("");

    const message = JSON.stringify({
      iss: "vendor",
      sub: "1234",
      exp: Date.now() + 10 * 60 * 1000, // expires in 10 minutes
      iat: Date.now(),
      bundle: "...",
    });

    console.log("########## PAYLOAD ##########");
    console.log(message);
    console.log("");

    const signed = await jose.JWS.createSign(privatekey)
      .update(message, "utf8")
      .final();

    console.log("########## SIGNED ##########");
    console.log(signed);
    console.log("");

    const encrypted = await jose.JWE.createEncrypt(symmetrickey)
      .update(JSON.stringify(signed), "utf8")
      .final();

    console.log("########## ENCRYPTED ##########");
    console.log(encrypted);
    console.log("");

    const decrypted = await jose.JWE.createDecrypt(symmetrickey).decrypt(
      encrypted
    );

    console.log("########## DECRYPTED ##########");
    console.log(decrypted);
    console.log("");

    const output = JSON.parse(decrypted.payload.toString());
    console.log("########## OUTPUT ##########");
    console.log(parsePayload(output.payload));
    console.log("");
  } catch (err) {
    console.log(err);
  }
};

main();
