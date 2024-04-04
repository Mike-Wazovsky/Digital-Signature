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
        p = generatePrime(keySize / 2)
        q = generatePrime(keySize / 2)

        n = p.multiply(q)
        m = (p - BigInteger.ONE).multiply(q - BigInteger.ONE)

        do {
            e = BigInteger(keySize, random)
        } while (e.gcd(m) != BigInteger.ONE)

        d = modInverse(e, m)
    }

    // the extended Euclidean algorithm
    fun modInverse(a: BigInteger, m: BigInteger): BigInteger {
        var a = a
        var m = m
        var x = BigInteger.ZERO
        var y = BigInteger.ONE
        var lastX = BigInteger.ONE
        var lastY = BigInteger.ZERO
        var temp: BigInteger

        while (m != BigInteger.ZERO) {
            val quotientAndRemainder = a.divideAndRemainder(m)
            val q = quotientAndRemainder[0]
            val r = quotientAndRemainder[1]

            a = m
            m = r

            temp = x
            x = lastX.subtract(q.multiply(x))
            lastX = temp

            temp = y
            y = lastY.subtract(q.multiply(y))
            lastY = temp
        }

        return if (lastX.compareTo(BigInteger.ZERO) < 0) lastX.add(m) else lastX
    }

    private fun generatePrime(bitLength: Int): BigInteger {
        var prime: BigInteger
        do {
            prime = BigInteger(bitLength, 100, random)
        } while (!prime.isProbablePrime(100))
        return prime
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
    for (i in 1..100) {
        val rsa = RSA(1024)

        val message = BigInteger.valueOf(123)

        val publicKey = rsa.getPublicKey()
        val privateKey = rsa.getPrivateKey()

        val encryptedMessage = rsa.encrypt(message, publicKey)
        println("Encrypted message: $encryptedMessage")

        val decryptedMessage = rsa.decrypt(encryptedMessage, privateKey)
        println("Decrypted message: $decryptedMessage")
    }
}