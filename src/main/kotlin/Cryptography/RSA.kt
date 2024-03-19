import java.math.BigInteger
import java.security.SecureRandom

class RSA(keySize: Int) {

    private val random = SecureRandom()

    private var p: BigInteger
    private var q: BigInteger
    private var n: BigInteger
    private var m: BigInteger
    private var e: BigInteger
    private var d: BigInteger

    init {
        p = BigInteger.probablePrime(keySize / 2, random)
        q = BigInteger.probablePrime(keySize / 2, random)

        n = p.multiply(q)
        m = (p - BigInteger.ONE).multiply(q - BigInteger.ONE)

        do {
            e = BigInteger(keySize, random)
        } while (e.gcd(m) != BigInteger.ONE)

        d = e.modInverse(m)
    }

    fun getPublicKey(): Pair<BigInteger, BigInteger> {
        return Pair(e, n)
    }

    fun getPrivateKey(): Pair<BigInteger, BigInteger> {
        return Pair(d, n)
    }

    fun encrypt(message: BigInteger, publicKey: Pair<BigInteger, BigInteger>): BigInteger {
        val (e, n) = publicKey
        return message.modPow(e, n)
    }

    fun decrypt(ciphertext: BigInteger, privateKey: Pair<BigInteger, BigInteger>): BigInteger {
        val (d, n) = privateKey
        return ciphertext.modPow(d, n)
    }
}

fun main() {
    val rsa = RSA(1024)

    val message = BigInteger.valueOf(123)

    val publicKey = rsa.getPublicKey()
    val privateKey = rsa.getPrivateKey()

    val encryptedMessage = rsa.encrypt(message, publicKey)
    println("Encrypted message: $encryptedMessage")

    val decryptedMessage = rsa.decrypt(encryptedMessage, privateKey)
    println("Decrypted message: $decryptedMessage")
}