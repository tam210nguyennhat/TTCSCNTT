
class ChunkCutter():
    @staticmethod
    def cut_into_chunks(data, chunk_size):
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunks.append(data[i:i + chunk_size])
        return chunks