// STM32 loader for binaries built from the STM232 Standard Peripheral Library
// Author: Franco Venturi
// Version: 1.0
// Based on: https://wrongbaud.github.io/posts/writing-a-ghidra-loader/

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainObject;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class STM32Loader extends AbstractProgramWrapperLoader {

    private FlatProgramAPI api;
    private Program program;
    private TaskMonitor monitor;
    private DataTypeManager dtmgr;
    private DataTypeManager stm32Dtmgr;
    private Address memAddr;
    private long fileAddr;
    private MessageLog log;

    @Override
    public String getName() {
        return "STM32 Loader (Standard Peripheral Library)";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();
        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default"), true));
        return loadSpecs;
    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.UNTARGETED_LOADER;
    }

    @Override
    public int getTierPriority() {
        return 101;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        api = new FlatProgramAPI(program, monitor);
        this.program = program;
        this.monitor = monitor;
        dtmgr = program.getDataTypeManager();
        this.log = log;

        //CompilerSpec compilerSpec = program.getCompilerSpec();
        //log.appendMsg("compilerSpec: " + compilerSpec.getLanguage().toString() + ":" + compilerSpec.getCompilerSpecDescription().toString());

        try {
            monitor.setMessage("STM32 Loader: starting loading");

            Map<String, Object> loadOptions = new HashMap<>();
            for (Option option: options) {
                loadOptions.put(option.getName(), option.getValue());
            }
            Address baseAddr = api.toAddr(Long.parseLong((String) loadOptions.get("Base address"), 16));

            memAddr = baseAddr;
            fileAddr = 0;

            File stm32GdtArchive = new File((String) loadOptions.get("STM32 GDT archive path"));
            stm32Dtmgr = api.openDataTypeArchive(stm32GdtArchive, true);

            Address isrVectorAddress = loadISRVector(provider);

            // load the rest as the text section for now
            // (we'll carve out the data and bss sections later)
            MemoryBlock textBlock = api.createMemoryBlock(".text", memAddr, provider.readBytes(fileAddr, provider.length() - fileAddr), false);
            textBlock.setRead(true);
            textBlock.setWrite(false);
            textBlock.setExecute(true);

            createHandlerFunctions(api.getDataAt(isrVectorAddress));
            Map<String, Long> resetHandlerUsefulInfo = parseResetHandler();
            resizeMemoryMapAndDefineFirstFunctions(resetHandlerUsefulInfo);
            addPeripherals();
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException(e);
        }
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean isLoadIntoProgram) {
        List<Option> list = new ArrayList<>();
        list.add(new Option("Base address", "08020000"));
        list.add(new Option("STM32 GDT archive path", "STM32F427_437xx.gdt"));
        list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram));

        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

        return super.validateOptions(provider, loadSpec, options, program);
    }

    private Address loadISRVector(ByteProvider provider) 
            throws Exception {
        DataType isrVectorType = stm32Dtmgr.getDataType(new DataTypePath("/", "ISRVector"));
        int isrVectorLength = isrVectorType.getLength();
        MemoryBlock isrVectorBlock = api.createMemoryBlock(".isr_vector", memAddr, provider.readBytes(0, isrVectorLength), false);
        isrVectorBlock.setRead(true);
        isrVectorBlock.setWrite(false);
        isrVectorBlock.setExecute(false);
        api.createData(memAddr, isrVectorType);
        api.createLabel(memAddr, "isr_vector", true);
        Address isrVectorAddress = memAddr;

        memAddr = memAddr.add(isrVectorLength);
        fileAddr += isrVectorLength;

        return isrVectorAddress;
    }

    private void createHandlerFunctions(Data isrVector)
            throws Exception {
        // 1. find default handler
        Map<Address, Integer> addressCounts = new HashMap<>();
        int numComponents = isrVector.getNumComponents();
        for (int i = 0; i < numComponents; i++) {
            DataType componentDataType = isrVector.getComponent(i).getDataType();
            // skip anything that is not a function pointer
            if (!(componentDataType instanceof Pointer))
                continue;
            DataType pointedToDataType = ((Pointer) componentDataType).getDataType();
            if (!(pointedToDataType instanceof FunctionSignature))
                continue;
            Address addr = (Address) isrVector.getComponent(i).getValue();
            // set the last bit to 0 because of Thumb 2
            addr = addr.getNewAddress(addr.getOffset() & ~1L);
            int count = addressCounts.getOrDefault(addr, 0);
            addressCounts.put(addr, count + 1);
        }

        Address defaultHandlerAddress = null;
        for (Map.Entry<Address, Integer> addressCount: addressCounts.entrySet()) {
            if (addressCount.getValue() == 1)
                continue;
            if (defaultHandlerAddress == null) {
                defaultHandlerAddress = addressCount.getKey();
            } else {
                throw new RuntimeException("found multiple default handlers");
            }
        }
        if (defaultHandlerAddress == null) {
            throw new RuntimeException("default handler not found");
        }

        // start with the default handler
        FunctionSignature defaultHandlerSignature = (FunctionSignature) stm32Dtmgr.getDataType(new DataTypePath("/functions", "Default_Handler"));
        createFunctionFromSignature(defaultHandlerAddress, defaultHandlerSignature);

        // add all the other handlers
        for (int i = 0; i < numComponents; i++) {
            DataType componentDataType = isrVector.getComponent(i).getDataType();
            // skip anything that is not a function pointer
            if (!(componentDataType instanceof Pointer))
                continue;
            DataType pointedToDataType = ((Pointer) componentDataType).getDataType();
            if (!(pointedToDataType instanceof FunctionSignature))
                continue;
            Address handlerAddress = (Address) isrVector.getComponent(i).getValue();
            // set the last bit to 0 because of Thumb 2
            handlerAddress = handlerAddress.getNewAddress(handlerAddress.getOffset() & ~1L);
            if (handlerAddress.equals(defaultHandlerAddress))
                continue;
            FunctionSignature handlerSignature = (FunctionSignature) stm32Dtmgr.getDataType(new DataTypePath("/functions", pointedToDataType.getName()));
            createFunctionFromSignature(handlerAddress, handlerSignature);
            api.addEntryPoint(handlerAddress);
        }

        api.addEntryPoint(defaultHandlerAddress);
    }

    // based on the method 'setSignature()' in 'Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/ApplyFunctionSignatureCmd.java' (lines 132-170)
    private Function createFunctionFromSignature(Address address, FunctionSignature signature)
            throws Exception {
        SourceType source = SourceType.USER_DEFINED;
        Function func = api.createFunction(address, signature.getName());
        func.setName(signature.getName(), source);
        String conventionName = signature.getCallingConventionName();
        func.setCallingConvention(conventionName);
        func.setComment(signature.getComment());
        List<Parameter> parameters = new ArrayList<>();
        for (ParameterDefinition arg: signature.getArguments()) {
            String name = arg.getName();
            DataType type = arg.getDataType().clone(dtmgr);
            Parameter parameter = new ParameterImpl(name, type, VariableStorage.UNASSIGNED_STORAGE, program);
            parameter.setComment(arg.getComment());
            parameters.add(parameter);
        }
        func.replaceParameters(parameters, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, source);
        func.setReturnType(signature.getReturnType(), source);
        func.setVarArgs(signature.hasVarArgs());
        func.setNoReturn(signature.hasNoReturn());
        func.setSignatureSource(source);
        return func;
    }

    private Map<String, Long> parseResetHandler()
            throws Exception {
        final long expectedFullHash = 0xc1108350dfdbdd3L;
        final long expectedSpecificHash = 0x6c5c108b013e99f9L;

        List<Function> resetHandlers = api.getGlobalFunctions("Reset_Handler");
        if (resetHandlers.size() == 0) {
            throw new RuntimeException("reset handler not found");
        }
        if (resetHandlers.size() > 1) {
            throw new RuntimeException("found multiple reset handlers");
        }
        Function resetHandler = resetHandlers.get(0);
        Address resetHandlerAddress = resetHandler.getEntryPoint();
        final int resetHandlerPresumedSize = 55;
        AddressSet resetHandlerBody = new AddressSet(resetHandlerAddress, resetHandlerAddress.add(resetHandlerPresumedSize));
        resetHandler.setBody(resetHandlerBody);

        // compute function id hash (FidHash) for Reset_Handler
        Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
        disassembler.disassemble(resetHandlerAddress, resetHandlerBody, true);
        FidService service = new FidService();
        FidHashQuad hashFunction = service.hashFunction(resetHandler);
        if (hashFunction == null) {
            throw new RuntimeException("Reset_Handler too small to compute a function hash");
        }
        if (!(hashFunction.getFullHash() == expectedFullHash && hashFunction.getSpecificHash() == expectedSpecificHash)) {
            throw new RuntimeException("Reset_Handler does not match the one in the Standard Peripheral Library");
        }

        // go though the instructions and extract usefult bits of information
        // see: STM32Cube/Repository/STM32Cube_FW_F4_V1.27.1/Drivers/CMSIS/Device/ST/STM32F4xx/Source/Templates/gcc/startup_stm32f427xx.s
        Map<String, Long> usefulInfo = new HashMap<>();
        Instruction instruction = api.getFirstInstruction(resetHandler);
        Long value = parseLdrInstruction(instruction);
        if (value != null) {
            usefulInfo.put("_estack", value);
        }
        instruction = instruction.getNext();
        instruction = instruction.getNext();
        value = parseLdrInstruction(instruction);
        if (value != null) {
            usefulInfo.put("_sdata", value);
        }
        instruction = instruction.getNext();
        value = parseLdrInstruction(instruction);
        if (value != null) {
            usefulInfo.put("_edata", value);
        }
        instruction = instruction.getNext();
        value = parseLdrInstruction(instruction);
        if (value != null) {
            usefulInfo.put("_sidata", value);
        }
        for (int i = 0; i < 9; i++) {
            instruction = instruction.getNext();
        }
        value = parseLdrInstruction(instruction);
        if (value != null) {
            usefulInfo.put("_sbss", value);
        }
        instruction = instruction.getNext();
        value = parseLdrInstruction(instruction);
        if (value != null) {
            usefulInfo.put("_ebss", value);
        }
        for (int i = 0; i < 7; i++) {
            instruction = instruction.getNext();
        }
        value = parseBlInstruction(instruction);
        if (value != null) {
            usefulInfo.put("SystemInit", value);
        }
        instruction = instruction.getNext();
        value = parseBlInstruction(instruction);
        if (value != null) {
            usefulInfo.put("__libc_init_array", value);
        }
        instruction = instruction.getNext();
        value = parseBlInstruction(instruction);
        if (value != null) {
            usefulInfo.put("main", value);
        }
        return usefulInfo;
    }

    private Long parseLdrInstruction(Instruction instruction)
            throws Exception {
        if (instruction.getMnemonicString().equals("ldr") && instruction.getNumOperands() == 2) {
            Object[] objects = instruction.getOpObjects(1);
            if (objects.length == 1 && objects[0] instanceof Address) {
                Address opAddress = (Address) objects[0];
                Data data = api.createData(opAddress, new Undefined4DataType());
                return ((Scalar) data.getValue()).getValue();
            }
        }
        log.appendMsg("invalid ldr instruction: " + instruction.toString());
        return null;
    }

    private Long parseBlInstruction(Instruction instruction)
            throws Exception {
        if (instruction.getMnemonicString().equals("bl") && instruction.getNumOperands() == 1) {
            Object[] objects = instruction.getOpObjects(0);
            if (objects.length == 1 && objects[0] instanceof Address) {
                Address funcAddress = (Address) objects[0];
                return funcAddress.getOffset();
            }
        }
        log.appendMsg("invalid bl instruction: " + instruction.toString());
        return null;
    }

    private void resizeMemoryMapAndDefineFirstFunctions(Map<String, Long> resetHandlerUsefulInfo)
        throws Exception {
        Address sidata = api.toAddr(resetHandlerUsefulInfo.get("_sidata"));
        api.createLabel(sidata, "_sidata", true);
        Memory memory = program.getMemory();
        MemoryBlock textBlock = memory.getBlock(".text");

        // data block
        memory.split(textBlock, sidata);
        MemoryBlock dataBlock = memory.getBlock(sidata);
        Address sdata = api.toAddr(resetHandlerUsefulInfo.get("_sdata"));
        api.createLabel(sdata, "_sdata", true);
        Address edata = api.toAddr(resetHandlerUsefulInfo.get("_edata"));
        api.createLabel(sdata, "_edata", true);
        long dataBlockSize = edata.getOffset() - sdata.getOffset();
        long dataBlockCurrentSize = dataBlock.getSize();
        if (dataBlockCurrentSize < dataBlockSize) {
            log.appendMsg("data block size is too small - expected at least " + dataBlockSize + " - got " + dataBlockCurrentSize);
            return;
        } else if (dataBlockCurrentSize > dataBlockSize) {
            String message = String.format("Firmware has extra %d bytes after end of data (edata) - .ccmram segment perhaps?", dataBlockCurrentSize - dataBlockSize);
            Msg.info(STM32Loader.class, message);
            log.appendMsg(message);
            //Address tail = api.toAddr(sidata.getOffset() + dataBlockSize);
            //memory.split(dataBlock, tail);
            //MemoryBlock tailBlock = memory.getBlock(tail);
            //tailBlock.setName("UNKNOWN");
            //api.createFragment("UNKNOWN", tailBlock.getStart(), tailBlock.getSize());
            Address siccmram = api.toAddr(sidata.getOffset() + dataBlockSize);
            memory.split(dataBlock, siccmram);
            MemoryBlock ccmramBlock = memory.getBlock(siccmram);
            ccmramBlock.setName(".ccmram?");
            ccmramBlock.setRead(true);
            ccmramBlock.setWrite(true);
            ccmramBlock.setExecute(false);
            //ccmramBlock.setVolatile(true);
            Address sccmram = api.toAddr(0x10000000L);
            api.createLabel(sdata, "_sccmram", true);
            memory.moveBlock(ccmramBlock, sccmram, monitor);
            api.createFragment(".ccmram?", ccmramBlock.getStart(), ccmramBlock.getSize());
            Address eccmram = sccmram.add(ccmramBlock.getSize());
            api.createLabel(eccmram, "_eccmram", true);
        }
        dataBlock.setName(".data");
        dataBlock.setRead(true);
        dataBlock.setWrite(true);
        dataBlock.setExecute(false);
        //dataBlock.setVolatile(true);
        memory.moveBlock(dataBlock, sdata, monitor);
        api.createFragment(".data", dataBlock.getStart(), dataBlock.getSize());

        // bss block (initialized to 0)
        Address sbss = api.toAddr(resetHandlerUsefulInfo.get("_sbss"));
        api.createLabel(sbss, "_sbss", true);
        Address ebss = api.toAddr(resetHandlerUsefulInfo.get("_ebss"));
        api.createLabel(ebss, "_ebss", true);
        MemoryBlock bssBlock = memory.createInitializedBlock(".bss", sbss, ebss.getOffset() - sbss.getOffset(), (byte)0, monitor, false);
        bssBlock.setRead(true);
        bssBlock.setWrite(true);
        bssBlock.setExecute(false);
        //bssBlock.setVolatile(true);

        // stack block (uninitialized)
        Address estack = api.toAddr(resetHandlerUsefulInfo.get("_estack"));
        api.createLabel(estack, "_estack", true);
        MemoryBlock stack = memory.createUninitializedBlock("stack", ebss, estack.getOffset() - ebss.getOffset(), false);
        stack.setRead(true);
        stack.setWrite(true);
        stack.setExecute(false);
        //stack.setVolatile(true);

        // functions called from Reset_Handler
        Address systemInitAddress = api.toAddr(resetHandlerUsefulInfo.get("SystemInit"));
        FunctionSignature systemInitSignature = (FunctionSignature) stm32Dtmgr.getDataType(new DataTypePath("/functions", "SystemInit"));
        createFunctionFromSignature(systemInitAddress, systemInitSignature);
        Address libcInitArrayAddress = api.toAddr(resetHandlerUsefulInfo.get("__libc_init_array"));
        Function libcInitArray = createVoidFunctionVoid(libcInitArrayAddress, "__libc_init_array");
        Address mainAddress = api.toAddr(resetHandlerUsefulInfo.get("main"));
        Function main = createVoidFunctionVoid(mainAddress, "main");
    }

    // creates a function of type: void f(void)
    private Function createVoidFunctionVoid(Address address, String name)
            throws Exception {
        SourceType source = SourceType.USER_DEFINED;
        Function func = api.createFunction(address, name);
        func.setName(name, source);
        func.setCallingConvention("default");
        func.setReturnType(new VoidDataType(), source);
        func.setVarArgs(false);
        func.setNoReturn(false);
        func.setSignatureSource(source);
        return func;
    }

    private void addPeripherals() throws Exception {
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace globalNamespace = program.getGlobalNamespace();
        Memory memory = program.getMemory();
        ProgramModule rootModule = program.getListing().getDefaultRootModule();

        Namespace namespace = symbolTable.getNamespace("Peripherals", globalNamespace);
        if (namespace == null) {
            namespace = symbolTable.createNameSpace(globalNamespace, "Peripherals", SourceType.ANALYSIS);
        }

        ProgramModule peripheralsModule = null;
        for (Group group : rootModule.getChildren()) {
            if ("Peripherals".equals(group.getName())) {
                peripheralsModule = (ProgramModule) group;
                break;
            }
        }
        if (peripheralsModule == null) {
            peripheralsModule = rootModule.createModule("Peripherals");
        }

        Pattern peripheralTypePattern = Pattern.compile("type=(\\w+)");
        Enum peripherals = (Enum) stm32Dtmgr.getDataType(new DataTypePath("/", "_PERIPHERALS_"));
        for (String peripheralName : peripherals.getNames()) {
            Address peripheralAddress = api.toAddr(peripherals.getValue(peripheralName));
            String comment = peripherals.getComment(peripheralName);
            Matcher m = peripheralTypePattern.matcher(comment);
            DataType peripheralType = null;
            if (m.matches()) {
                peripheralType = stm32Dtmgr.getDataType(new DataTypePath("/", m.group(1)));
            }
            //log.appendMsg(String.format("name=%s address=0x%08x type=[%s] length=%d end=0x%08x", peripheralName, peripheralAddress.getOffset(), m.group(1), peripheralType.getLength(), peripheralAddress.getOffset() + peripheralType.getLength()));

            // create memory block
            MemoryBlock peripheralMemoryBlock = memory.createUninitializedBlock(peripheralName, peripheralAddress, peripheralType.getLength(), false);
            peripheralMemoryBlock.setRead(true);
            peripheralMemoryBlock.setWrite(true);
            peripheralMemoryBlock.setExecute(false);
            peripheralMemoryBlock.setVolatile(true);

            api.createData(peripheralAddress, peripheralType);
            symbolTable.createLabel(peripheralAddress, peripheralName, namespace, SourceType.USER_DEFINED);

            peripheralsModule.reparent(peripheralName, rootModule);
        }        
    }
}
