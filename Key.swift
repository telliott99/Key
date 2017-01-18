import CommonCrypto
import DataHelper

public typealias Salt = BinaryData

public class Key: BinaryData {
    
    public var pw: String = ""
    
    public var salt: Salt = Salt()
    
    public convenience init(_ input: String) {
        // print("Key.init(_: String): \(input)")
        self.init(input.utf8.map { UInt8($0) })
        pw = input
        data = []
    }
    
    public convenience init(_ input: String, salt:Salt) {
        self.init(input.utf8.map { UInt8($0) })
        pw = input
        self.stretch(saltIn: salt)
    }
    
    public convenience init(_ input: Key) {
        self.init(input.pw.utf8.map { UInt8($0) })
        pw = input.pw
        self.stretch(saltIn: input.salt)
        assert(self.data == input.data)
    }
    
    public func stretch(saltIn: Salt = Salt()) {
        // turn a password into a key with sufficient randomness
        // by key "stretching"
        let pw = self.pw
        let pwBytes = pw.utf8.map { Int8($0) }
        let pwLen = pwBytes.count
        
        // Int8 not UInt8!
        // let pwPointer = UnsafePointer<Int8>(pwBytes)
        
        // typealias Salt = BinaryData
        
        var salt: Salt
        if saltIn.data.count == 0 {
            salt = BinaryData(nRandomBytes(6))
        } else{
            salt = saltIn
        }
        print("pw: \(pw)")
        print("salt: \(salt)")
        
        let saltLen = salt.data.count
        // UInt8 not Int8!
        let saltPointer = UnsafePointer<UInt8>(salt.data)
        
        let alg = CCPBKDFAlgorithm(kCCPBKDF2)
        
        let hmac = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        
        /*
         run with this to
         figure out how many rounds needed
         for 1000ms computation time
         
         let rounds = CCCalibratePBKDF(
         alg,
         pwLen,
         saltLen,
         hmac,
         Int(CC_SHA1_DIGEST_LENGTH),
         1000)
         
         however, I found out the result is variable!
         (but not in a Playground) !!
         
         */
        
        let rounds = UInt32(1500001)
        
        // Derive the key
        let key = Array<UInt8>(
            repeating: 0,
            count:Int(CC_SHA1_DIGEST_LENGTH))
        
        CCKeyDerivationPBKDF(
            alg,            // kCCPBKDF2
            pw,
            pwLen,
            saltPointer,
            saltLen,
            hmac,           // kCCPRFHmacAlgSHA1
            rounds,
            UnsafeMutablePointer<UInt8>(mutating: key),
            Int(CC_SHA1_DIGEST_LENGTH))
        
        self.salt = salt
        // CC_SHA1_DIGEST_LENGTH == 20
        //
        self.data = key
    }
    
    public override var description : String {
        get {
            let s1 = "data: \(BinaryData(self.data))"
            let s2 = "salt: \(BinaryData(self.salt.data))"
            return "pw:   \(self.pw)\n\(s1)\n\(s2)"
        }
    }
}

func testKey() {
    print("test Key")
    let password = "my secret"
    var key = Key(password)
    print("\(key)\n")
    
    key.stretch()
    print("\(key)\n")
    
    let salt = key.salt
    key = Key(password)
    key.stretch(saltIn: salt)
    print("\(key)\n")
}
