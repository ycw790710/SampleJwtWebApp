using Grpc.Core;
using Grpc.Net.Client;
using IntegrateAuthNameSpace;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SecureTokenHome;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SampleJwtConsoleApp
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var uriAddress = "https://localhost:7256";

            var token = SecureTokenHelper.GetServerToken();
            var credentials = CallCredentials.FromInterceptor(async (context, metadata) =>
            {
                metadata.Add("Authorization", $"{SecureTokenHelper.ServerBearer} {token}");
            });

            var handler = new SocketsHttpHandler
            {
                PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
                KeepAlivePingDelay = TimeSpan.FromSeconds(30),
                KeepAlivePingTimeout = TimeSpan.FromSeconds(15),
                EnableMultipleHttp2Connections = true,
            };
            handler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13;

            using GrpcChannel channel = GrpcChannel.ForAddress(uriAddress, new GrpcChannelOptions
            {
                Credentials = ChannelCredentials.Create(new SslCredentials(), credentials),
                HttpHandler = handler
            });
            await channel.ConnectAsync();
            Console.WriteLine($"channel.State: {channel.State}");
            Console.WriteLine($"channel.Target: {channel.Target}");
            Console.WriteLine();

            await TestGrpcIteration(channel);
            await TestGrpcIteration(channel);
            TestGrpcTasks(channel);
            TestGrpcTasks(channel);

            Console.WriteLine("---END---");
            Console.Read();
        }

        static async Task TestGrpcIteration(GrpcChannel channel)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"---ValidateToken, 重複使用channel和client---");
            Console.ResetColor();

            var client = new IntegrateAuthGrpcService.IntegrateAuthGrpcServiceClient(channel);

            Stopwatch sw = new();
            int processedCount = 0;
            int targetMilliseconds = 3000;

            sw.Start();
            while (sw.ElapsedMilliseconds <= targetMilliseconds)
            {
                await TestProcess(client);

                Interlocked.Increment(ref processedCount);
                Console.Write($"\rcount: {processedCount}");
            }
            Console.WriteLine();
            sw.Stop();

            Console.WriteLine($"Elapsed Milliseconds: {sw.ElapsedMilliseconds}");
            Console.WriteLine($"processed count: {processedCount}");
            Console.WriteLine();
        }

        private static async Task TestProcess(IntegrateAuthGrpcService.IntegrateAuthGrpcServiceClient client)
        {
            var request = new ValidateTokenRequest()
            {
                UserToken = SecureTokenHelper.GetUserToken()
            };
            var reply = await client.ValidateTokenAsync(request);

            List<Claim> claims = new();
            foreach (var claim in reply.Claims)
            {
                claims.Add(new Claim(claim.Key, claim.Value, claim.ValueType));
            }

            var identity = new ClaimsIdentity(claims, JwtBearerDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, JwtBearerDefaults.AuthenticationScheme);
        }

        static void TestGrpcTasks(GrpcChannel channel)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"---並行處理 ValidateToken, 重複使用channel, 不重複使用client---");
            Console.ResetColor();

            Stopwatch sw = new();
            int processedCount = 0;
            int targetMilliseconds = 3000;
            ManualResetEventSlim manualResetEventSlim = new(false);
            int taskCount = 100;
            ThreadPool.SetMinThreads(101, 3);// here for test

            int readyCount = 0;
            int finishedCount = 0;

            object _lockCreateClientTicks = new();
            long createClientTicks = 0;

            for (int i = 0; i < taskCount; i++)
            {
                var processId = i;
                Task.Run(async () =>
                {
                    var dataId = 0;

                    Stopwatch swClient = new();
                    Interlocked.Increment(ref readyCount);
                    manualResetEventSlim.Wait();
                    while (sw.ElapsedMilliseconds <= targetMilliseconds)
                    {
                        swClient.Start();
                        var client = new IntegrateAuthGrpcService.IntegrateAuthGrpcServiceClient(channel);
                        swClient.Stop();

                        await TestProcess(client);

                        Interlocked.Increment(ref processedCount);
                        dataId++;
                    }
                    lock (_lockCreateClientTicks)
                        createClientTicks += swClient.ElapsedTicks;
                    Interlocked.Increment(ref finishedCount);
                });
            }

            Console.WriteLine($"tasks count: {taskCount}");
            while (readyCount < taskCount)
            {
                var pre = readyCount;
                SpinWait.SpinUntil(() => pre != readyCount || readyCount == taskCount);
                Console.Write($"\r準備task進度: {readyCount}/{taskCount}");
            }
            Console.WriteLine();

            sw.Start();
            manualResetEventSlim.Set();
            while (finishedCount < taskCount)
            {
                var pre = finishedCount;
                SpinWait.SpinUntil(() => pre != finishedCount || finishedCount == taskCount);
                Console.Write($"\r完成task進度: {finishedCount}/{taskCount}");
            }
            Console.WriteLine();
            sw.Stop();

            Console.WriteLine($"create client milliseconds: {createClientTicks * 1000 / Stopwatch.Frequency}");
            Console.WriteLine($"Elapsed Milliseconds: {sw.ElapsedMilliseconds}");
            Console.WriteLine($"processed count: {processedCount}");
            Console.WriteLine();

        }


    }
}