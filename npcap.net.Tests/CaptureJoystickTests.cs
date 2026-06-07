using npcap.net.Bridge;

namespace npcap.net.Tests
{
    [TestClass]
    public class CaptureJoystickTests
    {
        private static (CaptureJoystick Joystick, CancellationTokenSource Cts, Task Producer, Task Consumer, Task Waiter) MakeJoystick(
            Task? waiter = null)
        {
            var cts = new CancellationTokenSource();
            var producer = Task.FromResult(0);
            var consumer = Task.FromResult(0);
            var actualWaiter = waiter ?? Task.FromResult(0);

            var joystick = new CaptureJoystick();
            joystick.Set(actualWaiter, producer, consumer, cts);
            return (joystick, cts, producer, consumer, actualWaiter);
        }

        [TestMethod]
        public void Set_StoresAllComponents()
        {
            var (joystick, cts, producer, consumer, waiter) = MakeJoystick();
            var inst = (ICaptureJoystick)joystick;

            Assert.AreSame(cts, inst.Cts);
            Assert.AreSame(producer, inst.ProducerTask);
            Assert.AreSame(consumer, inst.ConsumerTask);
            Assert.AreSame(waiter, inst.WaiterTask);
        }

        [TestMethod]
        public void Stop_SignalsCancellation()
        {
            var (joystick, cts, _, _, _) = MakeJoystick();

            ((ICaptureJoystick)joystick).Stop();

            Assert.IsTrue(cts.IsCancellationRequested);
        }

        [TestMethod]
        public void Stop_BlocksUntilWaiterCompletes()
        {
            var waiterTcs = new TaskCompletionSource();
            var (joystick, _, _, _, _) = MakeJoystick(waiterTcs.Task);

            // Release the waiter slightly after Stop() is called
            var releaseTask = Task.Delay(50).ContinueWith(_ => waiterTcs.SetResult());
            var stopTask = Task.Run(() => ((ICaptureJoystick)joystick).Stop());

            Assert.IsTrue(stopTask.Wait(TimeSpan.FromSeconds(2)), "Stop() should return once the waiter completes");
        }

        [TestMethod]
        public void Stop_CalledTwice_DoesNotThrow()
        {
            var (joystick, _, _, _, _) = MakeJoystick();
            var inst = (ICaptureJoystick)joystick;

            inst.Stop();
            // CTS is already cancelled; second call must not throw
            inst.Stop();
        }

        [TestMethod]
        public async Task StopAsync_SignalsCancellation()
        {
            var (joystick, cts, _, _, _) = MakeJoystick();

            await ((ICaptureJoystick)joystick).StopAsync();

            Assert.IsTrue(cts.IsCancellationRequested);
        }

        [TestMethod]
        public async Task StopAsync_AwaitsWaiterTask()
        {
            var waiterTcs = new TaskCompletionSource();
            var (joystick, _, _, _, _) = MakeJoystick(waiterTcs.Task);

            var stopTask = ((ICaptureJoystick)joystick).StopAsync();
            Assert.IsFalse(stopTask.IsCompleted, "StopAsync should not complete before the waiter");

            waiterTcs.SetResult();
            await stopTask.WaitAsync(TimeSpan.FromSeconds(2));
        }

        [TestMethod]
        public async Task StopAsync_CalledTwice_DoesNotThrow()
        {
            var (joystick, _, _, _, _) = MakeJoystick();
            var inst = (ICaptureJoystick)joystick;

            await inst.StopAsync();
            await inst.StopAsync();
        }
    }
}
