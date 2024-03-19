import java.math.BigInteger

class Verificator {
    val rsa: RSA = RSA(2048)

    fun sign(message: String, publicKey: Pair<BigInteger, BigInteger>): BigInteger {
        val messageBytes = message.toByteArray()
        val messageBigInt = BigInteger(messageBytes)
        return rsa.encrypt(messageBigInt, publicKey)
    }

    fun verify(message: String, signature: BigInteger, privateKey: Pair<BigInteger, BigInteger>): Boolean {
        val decryptedSignature = rsa.decrypt(signature, privateKey)
        val decryptedMessageBytes = decryptedSignature.toByteArray()
        val decryptedMessage = String(decryptedMessageBytes)
        return decryptedMessage == message
    }
}

fun main() {
    val verificator = Verificator()

    val message = "Hello, RSA!"
    val publicKey = verificator.rsa.getPublicKey()
    val privateKey = verificator.rsa.getPrivateKey()

    val signature = verificator.sign(message, privateKey)
    println("Signature: $signature")

    val verified = verificator.verify(message, signature, publicKey)
    println("Verified: $verified")
}