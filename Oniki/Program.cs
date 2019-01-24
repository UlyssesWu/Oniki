using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Myrmec;

namespace Oniki
{
    class Program
    {
        static Sniffer _sniffer = new Sniffer();
        static void Main(string[] args)
        {
            Console.WriteLine("Oniki NPK Unpacker");
            Console.WriteLine("by Ulysses, wdwxy12345@gmail.com");
            Console.WriteLine();
            if (args.Length == 0)
            {
                Console.WriteLine("No input!");
                return;
            }

            InitSniffer();

            if (args.Length == 1)
            {
                Unpack(args[0], "output");
            }

            if (args.Length > 1)
            {
                if (args.Last() == "-a" || args.Last() == "-aggressive")
                {
                    if (args.Length >= 3)
                    {
                        Unpack(args[0], args[1]);
                        TridInfer(args[1]);
                    }
                    else
                    {
                        Unpack(args[0], "output");
                        TridInfer("output");
                    }
                }
                else
                {
                    Unpack(args[0], args[1]);
                }
            }
            Console.ReadLine();
        }

        static void InitSniffer()
        {
            _sniffer.Populate(new List<Record>()
            {
                new Record("ttf", "00 01 00 00 00"),
                new Record("asf wma wmv", "30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C"),
                new Record("ogg oga ogv", "4F 67 67 53"),
                new Record("psd", "38 42 50 53"),
                new Record("mp3", "FF FB"),
                new Record("mp3", "49 44 33"),
                new Record("bmp dib", "42 4D"),
                new Record("jpg,jpeg", "ff,d8,ff,db"),
                new Record("png", "89,50,4e,47,0d,0a,1a,0a"),
                new Record("zip,jar,odt,ods,odp,docx,xlsx,pptx,vsdx,apk,aar", "50,4b,03,04"),
                new Record("zip,jar,odt,ods,odp,docx,xlsx,pptx,vsdx,apk,aar", "50,4b,07,08"),
                new Record("zip,jar,odt,ods,odp,docx,xlsx,pptx,vsdx,apk,aar", "50,4b,05,06"),
                new Record("rar", "52,61,72,21,1a,07,00"),
                new Record("rar", "52,61,72,21,1a,07,01,00"),
                new Record("ico", "00 00 01 00"),
                new Record("z,tar.z", "1F 9D"),
                new Record("z,tar.z", "1F A0"),
                new Record("gif", "47 49 46 38 37 61"),
                new Record("gif", "47 49 46 38 39 61"),
                new Record("exe", "4D 5A"),
                new Record("tar", "75 73 74 61 72", 257),
                new Record("xml", "3c 3f 78 6d 6c 20"),
                new Record("7z", "37 7A BC AF 27 1C"),
                new Record("jpg,jpeg","FF D8 FF E0 ?? ?? 4A 46 49 46 00 01"),
                new Record("jpg,jpeg","FF D8 FF E1 ?? ?? 45 78 69 66 00 00"),
                //ADDED
                new Record("xml", "EF BB BF 3C 3F 78 6D 6C"), //xml with BOM
                new Record("ktx", "AB 4B 54 58"), //KTX
                new Record("unkModel","34 80 C8 BB"),
            });
        }

        static void Unpack(string npk, string dir)
        {
            if (!File.Exists(npk))
            {
                Console.WriteLine("Can not find npk file.");
                return;
            }
            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var fs = File.OpenRead(npk);
            var br = new BinaryReader(fs);

            var len = fs.Length;
            fs.Seek(20, SeekOrigin.Begin);
            var mapOffset = br.ReadUInt32(); //begin: res bytes, end: map

            List<NItem> items = new List<NItem>();

            fs.Seek(mapOffset, SeekOrigin.Begin);
            while (fs.Position + 4 * 7 <= len)
            {
                var item = new NItem
                {
                    Id = br.ReadUInt32(),
                    Offset = br.ReadUInt32(),
                    CompressedLength = br.ReadUInt32(),
                    OriginalLength = br.ReadUInt32(),
                    Unk4 = br.ReadUInt32(),
                    Unk5 = br.ReadUInt32(),
                    IsCompressed = br.ReadUInt32(),
                };
                //if (item.Id == 0x694FDF33 || item.Unk4 == 0x694FDF33 || item.Unk5 == 0x694FDF33)
                //{
                //    Console.WriteLine("maybe have name");
                //}
                items.Add(item);
            }

            items.Sort((o1, o2) => (int)((long)o1.Offset - (long)o2.Offset));
            List<Task> tasks = new List<Task>(items.Count);

            foreach (var it in items)
            {
                fs.Seek(it.Offset, SeekOrigin.Begin);
                var bts = br.ReadBytes((int)it.CompressedLength);
                tasks.Add(Decompress(bts, dir, it));
            }

            Task.WaitAll(tasks.ToArray());
            Console.WriteLine("Done.");
            br.Dispose();
        }

        static async Task Decompress(byte[] bts, string dir, NItem item)
        {
            if (item.IsCompressed == 0 || (item.Unk4 == item.Unk5 && item.OriginalLength == item.CompressedLength))
            {
                //Console.WriteLine($"Unpack {item.Id:X8}");
                var header = bts.Take(32).ToArray();
                var fileName = InferExtension(header, item, out var category);
                Console.WriteLine($"Unpack: {fileName}");
                var path = Path.Combine(dir, category);
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }

                using (var fs = File.Create(Path.Combine(path, fileName)))
                {
                    await fs.WriteAsync(bts, 0, bts.Length);
                }
            }
            else
            {
                //Console.WriteLine($"Decompress: {item.Id:X8}");
                using (var output = new MemoryStream((int)item.OriginalLength))
                {
                    try
                    {
                        using (var ms = new MemoryStream(bts, 2, bts.Length - 2))
                        using (var zs = new DeflateStream(ms, CompressionMode.Decompress, false))
                        {
                            await zs.CopyToAsync(output);
                            output.Position = 0;
                        }
                    }
                    catch (InvalidDataException e)
                    {
                        Console.WriteLine($"Decompress {item.Id:X8}({item.Offset}) failed.");
                    }

                    var header = new byte[32];
                    await output.ReadAsync(header, 0, header.Length);
                    var fileName = InferExtension(header, item, out var category);
                    Console.WriteLine($"Decompress: {fileName}");
                    var path = Path.Combine(dir, category);
                    if (!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                    }

                    output.Position = 0;
                    using (var fs = File.Create(Path.Combine(path, fileName)))
                    {
                        await output.CopyToAsync(fs);
                    }
                }
            }
        }

        static void TridInfer(string path)
        {
            if (!File.Exists("trid.exe"))
            {
                return;
            }
            //StringBuilder sb = new StringBuilder();
            //DirectoryInfo di = new DirectoryInfo(path);
            //foreach (var file in di.EnumerateFiles("????????"))
            //{
            //    sb.Append($"\"{file.FullName}\" ");
            //}
            //sb.Append("-ae");
            if (path.EndsWith("\\"))
            {
                path += "*";
            }
            else if (!path.EndsWith("\\*"))
            {
                path += "\\*";
            }
            Process.Start("trid.exe", path + " -ce");
        }

        static string InferExtension(byte[] header, NItem item, out string category)
        {
            var result = _sniffer.Match(header);
            if (result.Count == 0)
            {
                var headerStr = Encoding.ASCII.GetString(header);
                if (headerStr.StartsWith("KTX")
                    || headerStr.StartsWith("«KTX"))
                {
                    category = "texture";
                    return $"{item.Id:X8}.ktx";
                }
                if (headerStr.StartsWith("PKM"))
                {
                    category = "texture";
                    return $"{item.Id:X8}.pkm";
                }
                if (headerStr.StartsWith("RGIS"))
                {
                    category = "rgis";
                    return $"{item.Id:X8}.rgis";
                }
                if (headerStr.StartsWith("<NeoX")
                    || headerStr.StartsWith("<Neox"))
                {
                    category = "NeoXml";
                    return $"{item.Id:X8}.NeoX.xml";
                }
                if (headerStr.StartsWith("<FxGroup"))
                {
                    category = "NeoXml";
                    return $"{item.Id:X8}.FxGroup.xml";
                }
                if (headerStr.StartsWith("<SceneMusic"))
                {
                    category = "NeoXml";
                    return $"{item.Id:X8}.SceneMusic.xml";
                }
                if (headerStr.StartsWith("<MusicTriggers"))
                {
                    category = "NeoXml";
                    return $"{item.Id:X8}.MusicTriggers.xml";
                }
                if (headerStr.StartsWith("<cinematic"))
                {
                    category = "NeoXml";
                    return $"{item.Id:X8}.cinematic.xml";
                }
                if (headerStr.StartsWith("<EquipList"))
                {
                    category = "NeoXml";
                    return $"{item.Id:X8}.EquipList.xml";
                }
                if (headerStr.StartsWith("<SceneConfig"))
                {
                    category = "NeoXml";
                    return $"{item.Id:X8}.SceneConfig.xml";
                }
                if (headerStr.StartsWith("<SceneRoad"))
                {
                    category = "NeoXml";
                    return $"{item.Id:X8}.SceneRoad.xml";
                }

                if (headerStr.StartsWith("v ")
                    || headerStr.StartsWith("vt ")
                    || headerStr.StartsWith("f ")
                )
                {
                    category = "model";
                    return $"{item.Id:X8}.obj";
                }
                if (headerStr.StartsWith("CocosStudio-UI"))
                {
                    category = "ui";
                    return $"{item.Id:X8}.csb";
                }
                if (headerStr.StartsWith("vec4")
                    || headerStr.StartsWith("vec2")
                    || headerStr.StartsWith("tex2D")
                    || headerStr.StartsWith("tex3D")
                    || headerStr.StartsWith("float")
                    || headerStr.StartsWith("define")
                    || headerStr.StartsWith("incloud")
                    || headerStr.StartsWith("#if")
                    || headerStr.StartsWith("#define")
                    || headerStr.StartsWith("int ")
                    || headerStr.StartsWith("precision ")
                )
                {
                    category = "shader";
                    return $"{item.Id:X8}.glsl";
                }
                if (headerStr.StartsWith("{"))
                {
                    category = "json";
                    return $"{item.Id:X8}.json";
                }

                if (header.Length >= 32 && header[0] != 0 && header.Skip(16).Take(16).All(b => b == 0))
                {
                    category = "unknown";
                    return $"{item.Id:X8}.unkAnim";
                }
                category = "";
                return item.Id.ToString("X8");
            }

            var ext = result[0];
            switch (ext)
            {
                case "jpg":
                case "jpeg":
                case "png":
                case "gif":
                case "ico":
                case "bmp":
                case "psd":
                    category = "image";
                    break;
                case "xml":
                    category = "xml";
                    break;
                case "ktx":
                    category = "texture";
                    break;
                case "unkModel":
                    category = "unknown";
                    break;
                default:
                    category = "";
                    break;
            }

            return $"{item.Id:X8}.{ext}";
        }

        static void Test()
        {
            Unpack(@"../../res/res.npk", "NPK");
        }
    }

    class NItem
    {
        public uint Id; //0
        public uint Offset; //1
        public uint CompressedLength; //2
        public uint OriginalLength; //3
        public uint Unk4;
        public uint Unk5;
        public uint IsCompressed; //6
    }
}
