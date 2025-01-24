namespace ConcasDev.Security.Memory.Test
{
    public class Test
    {
        [Fact]
        public void CreateSecretAndClearRawDataBytesTest()
        {
            // Arrange
            var rawData = new byte[5] { 10, 33, 42, 95, 2 };

            // Act
            using var secret = MemoryProtection.SecureData(rawData);

            // Assert
            Assert.Equal(rawData.Length, secret.Length);
            Assert.All(rawData, b => Assert.Equal(0, b));
        }

        [Fact]
        public void ObtainSecretDataBytesTest()
        {
            // Arrange
            var rawData = new byte[5] { 10, 33, 42, 95, 2 };
            var rawDataClone = rawData.Clone(); // Needed for assert
            using var secret = MemoryProtection.SecureData(rawData);

            // Act
            var data = MemoryProtection.GetData<byte[]>(secret);

            // Assert
            Assert.Equal(rawDataClone, data);
        }

        [Fact]
        public void ClearSecretDataBytesAfterUseTest()
        {
            // Arrange
            var rawData = new byte[5] { 10, 33, 42, 95, 2 };
            using var secret = MemoryProtection.SecureData(rawData);
            var data = MemoryProtection.GetData<byte[]>(secret);

            // Act
            data.Clear();

            // Assert
            Assert.Equal(data.Length, secret.Length);
            Assert.All(data, b => Assert.Equal(0, b));
        }

        [Fact]
        public void CreateSecretAndClearRawDataCharsTest()
        {
            // Arrange
            var rawData = new char[5] { 'b', 'f', 'u', 'a', 't' };

            // Act
            using var secret = MemoryProtection.SecureData(rawData);

            // Assert
            Assert.Equal(rawData.Length, secret.Length);
            Assert.All(rawData, b => Assert.Equal(0, b));
        }

        [Fact]
        public void ObtainSecretDataCharsTest()
        {
            // Arrange
            var rawData = new char[5] { 'b', 'f', 'u', 'a', 't' };
            var rawDataClone = rawData.Clone(); // Needed for assert
            using var secret = MemoryProtection.SecureData(rawData);

            // Act
            var data = MemoryProtection.GetData<char[]>(secret);

            // Assert
            Assert.Equal(rawDataClone, data);
        }

        [Fact]
        public void ClearSecretDataCharsAfterUseTest()
        {
            // Arrange
            var rawData = new char[5] { 'b', 'f', 'u', 'a', 't' };
            using var secret = MemoryProtection.SecureData(rawData);
            var data = MemoryProtection.GetData<char[]>(secret);

            // Act
            data.Clear();

            // Assert
            Assert.Equal(data.Length, secret.Length);
            Assert.All(data, b => Assert.Equal(0, b));
        }
    }
}