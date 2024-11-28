class A51Cipher:
    def __init__(self, key):
        """
        A5/1 shifrlash algoritmini 64-bitli kalit bilan inicializatsiya qilish.
        :param key: 64-bitli ikkilik satr (binar satr)
        """
        if len(key) != 64:
            raise ValueError("Kalit 64 bitli bo'lishi kerak.")
        
        # Kalitni bo‘lib olish: LFSR1 (19 bit), LFSR2 (22 bit), LFSR3 (23 bit)
        self.initial_lfsr1 = [int(bit) for bit in key[:19]]  # LFSR1: 19 bit
        self.initial_lfsr2 = [int(bit) for bit in key[19:41]]  # LFSR2: 22 bit
        self.initial_lfsr3 = [int(bit) for bit in key[41:]]  # LFSR3: 23 bit

        # Ishlash uchun LFSRlarni boshlang'ich holatiga qaytarish
        self.reset()

        # Feed-back uchun teskari bitlar (tap positions)
        self.taps = {
            "lfsr1": [13, 16, 17, 18],  # LFSR1 uchun feed-back pozitsiyalari
            "lfsr2": [20, 21],          # LFSR2 uchun feed-back pozitsiyalari
            "lfsr3": [7, 20, 21, 22]    # LFSR3 uchun feed-back pozitsiyalari
        }

        # Ko‘pchilik ovoz (majority voting) uchun bit pozitsiyalari
        self.majority_bits = [8, 10, 10]  # LFSR bitlari

    def reset(self):
        """
        LFSRlarni boshlang'ich holatiga qaytarish.
        """
        self.lfsr1 = self.initial_lfsr1[:]
        self.lfsr2 = self.initial_lfsr2[:]
        self.lfsr3 = self.initial_lfsr3[:]

    def majority_vote(self):
        """
        LFSRlarning clocking bitlari bo‘yicha ko‘pchilik ovozini hisoblash.
        """
        bits = [self.lfsr1[self.majority_bits[0]], 
                self.lfsr2[self.majority_bits[1]], 
                self.lfsr3[self.majority_bits[2]]]
        return 1 if sum(bits) > 1 else 0

    def step(self):
        """
        LFSRlarni ko‘pchilik ovozi bo‘yicha bir qadam ilgari surish va 1 bitlik kalit oqimini yaratish.
        """
        majority = self.majority_vote()

        # Har bir LFSRni clocking bitiga qarab yangilash
        if self.lfsr1[self.majority_bits[0]] == majority:
            feedback = sum(self.lfsr1[i] for i in self.taps["lfsr1"]) % 2
            self.lfsr1 = [feedback] + self.lfsr1[:-1]

        if self.lfsr2[self.majority_bits[1]] == majority:
            feedback = sum(self.lfsr2[i] for i in self.taps["lfsr2"]) % 2
            self.lfsr2 = [feedback] + self.lfsr2[:-1]

        if self.lfsr3[self.majority_bits[2]] == majority:
            feedback = sum(self.lfsr3[i] for i in self.taps["lfsr3"]) % 2
            self.lfsr3 = [feedback] + self.lfsr3[:-1]

        # Keystream bitini olish (har bir LFSRning oxirgi bitini XOR qilish orqali)
        return self.lfsr1[-1] ^ self.lfsr2[-1] ^ self.lfsr3[-1]

    def generate_keystream(self, length):
        """
        Berilgan uzunlikdagi kalit oqimini yaratish.
        :param length: Yaratiladigan bitlar soni
        :return: Keystream (bitlar ro‘yxati)
        """
        return [self.step() for _ in range(length)]

    def encrypt(self, plaintext):
        """
        Ochiq matnni kalit oqimi yordamida shifrlash.
        :param plaintext: Ochiq matn (0 va 1'lar bilan yozilgan satr)
        :return: Shifrlangan matn (0 va 1'lar bilan yozilgan satr)
        """
        self.reset()  # LFSRlarni qayta boshlash
        plaintext_bits = [int(bit) for bit in plaintext]
        keystream = self.generate_keystream(len(plaintext_bits))
        return ''.join(str(plaintext_bits[i] ^ keystream[i]) for i in range(len(plaintext_bits)))

    def decrypt(self, ciphertext):
        """
        Shifrlangan matnni kalit oqimi yordamida deshifrlash (shifrlash bilan bir xil jarayon).
        :param ciphertext: Shifrlangan matn (0 va 1'lar bilan yozilgan satr)
        :return: Ochiq matn (0 va 1'lar bilan yozilgan satr)
        """
        return self.encrypt(ciphertext)  # XOR qilish orqali asl matnni qaytarish


# Misol uchun foydalanish
if __name__ == "__main__":
    key = "1101001110111100100101101101111010100100111101111010010011011010"  # 64-bitli kalit
    plaintext = "10101010101010101010101010101010101010101010101"  # Ochiq matn (binar satr)

    cipher = A51Cipher(key)  # Klassni yaratish
    ciphertext = cipher.encrypt(plaintext)  # Shifrlash
    decrypted = cipher.decrypt(ciphertext)  # Deshifrlash

    # Natijalarni chiqarish
    print("Ochiq matn: ", plaintext)  # Ochiq matn
    print("Shifrlangan matn:", ciphertext)  # Shifrlangan matn
    print("Deshifrlangan matn: ", decrypted)  # Deshifrlangan matn (asl matn bilan bir xil bo'lishi kerak)
