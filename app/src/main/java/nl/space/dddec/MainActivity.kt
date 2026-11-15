package nl.space.dddec

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.Image
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import nl.space.dddec.ui.DecryptViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val isDark = isSystemInDarkTheme()
            MaterialTheme(colorScheme = if (isDark) darkColorScheme() else lightColorScheme()) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(viewModel: DecryptViewModel = viewModel()) {

    val pickKeysFile = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> viewModel.onKeysFileSelected(uri) }

    val pickSeedDb = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> viewModel.onSeedDbSelected(uri) }

    val pickCiaFile = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris -> viewModel.onCiaFilesSelected(uris) }

    val pickBatchDest = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri -> uri?.let { viewModel.startBatchProcessing(it) } }

    val createDestFile = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri -> viewModel.onDestinationSelected(uri) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("DDDs Decryptor", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor    = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                ),
                actions = {
                    if (viewModel.keyStore.isUsable || viewModel.seedDbMap != null) {
                        TextButton(onClick = { pickKeysFile.launch(arrayOf("*/*")) }) {
                            Icon(Icons.Default.Refresh, contentDescription = null)
                            Spacer(Modifier.width(4.dp))
                            Text("Keys")
                        }
                        TextButton(onClick = { pickSeedDb.launch(arrayOf("*/*")) }) {
                            Icon(Icons.Default.Refresh, contentDescription = null)
                            Spacer(Modifier.width(4.dp))
                            Text("SeedDB")
                        }
                    }
                }
            )
        }
    ) { padding ->
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            val isLandscape = maxWidth > 600.dp

            if (isLandscape) {
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 24.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .verticalScroll(rememberScrollState()),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Spacer(Modifier.height(24.dp))
                        StepCards(viewModel, pickKeysFile, pickSeedDb, pickCiaFile, createDestFile, pickBatchDest)
                        Spacer(Modifier.height(24.dp))
                    }
                    Spacer(Modifier.width(24.dp))
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .verticalScroll(rememberScrollState()),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Spacer(Modifier.height(24.dp))
                        ProgressAndStatus(viewModel)
                        Spacer(Modifier.height(24.dp))
                    }
                }
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 24.dp)
                        .verticalScroll(rememberScrollState()),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Spacer(Modifier.height(24.dp))
                    StepCards(viewModel, pickKeysFile, pickSeedDb, pickCiaFile, createDestFile, pickBatchDest)
                    Spacer(Modifier.height(32.dp))
                    ProgressAndStatus(viewModel)
                    Spacer(Modifier.height(32.dp))
                }
            }
        }
    }
}

@Composable
fun StepCards(
    viewModel: DecryptViewModel,
    pickKeysFile: androidx.activity.result.ActivityResultLauncher<Array<String>>,
    pickSeedDb:   androidx.activity.result.ActivityResultLauncher<Array<String>>,
    pickCiaFile:  androidx.activity.result.ActivityResultLauncher<Array<String>>,
    createDestFile: androidx.activity.result.ActivityResultLauncher<String>,
    pickBatchDest:  androidx.activity.result.ActivityResultLauncher<Uri?>
) {
    val keysLoaded  = viewModel.keyStore.isUsable
    val seedsLoaded = viewModel.seedDbMap != null
    val isBatch     = viewModel.batchQueue.isNotEmpty()
    val ready       = keysLoaded  // no keys ship with the app; seeddb is only needed for seeded titles

    // Step 1a: Keys file
    StepCard(
        title       = "1. Crypto Keys",
        description = if (keysLoaded) "${viewModel.keyStore.keyCount} keys loaded (aes_keys.txt)"
        else "Required — dump from your 3DS with GodMode9",
        icon        = Icons.Default.Lock,
        isCompleted = keysLoaded,
        enabled     = !viewModel.isProcessing,
        onClick     = { pickKeysFile.launch(arrayOf("*/*")) }
    )

    Spacer(Modifier.height(12.dp))

    // Step 1b: SeedDB
    StepCard(
        title       = "2. Seed Database",
        description = if (seedsLoaded) "${viewModel.seedDbMap?.size} entries loaded (seeddb.bin)"
        else "Optional — needed for seeded titles (seeddb.bin)",
        icon        = Icons.Default.List,
        isCompleted = seedsLoaded,
        enabled     = !viewModel.isProcessing,
        onClick     = { pickSeedDb.launch(arrayOf("*/*")) }
    )

    Spacer(Modifier.height(16.dp))

    // Step 2: Input
    StepCard(
        title       = "3. Input Content",
        description = when {
            isBatch                   -> "${viewModel.batchQueue.size} files selected"
            viewModel.ciaFileUri != null ->
                viewModel.ciaFileUri?.path?.split("/")?.lastOrNull() ?: "File selected"
            else                      -> "Select .cia or .3ds files (multi-select supported)"
        },
        icon        = if (isBatch) Icons.Default.List else Icons.Default.Add,
        isCompleted = viewModel.ciaFileUri != null || isBatch,
        enabled     = !viewModel.isProcessing && ready,
        onClick     = { pickCiaFile.launch(arrayOf("*/*")) }
    )

    Spacer(Modifier.height(12.dp))

    // Output format toggle
    Row(
        modifier             = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment    = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text("Output Format", style = MaterialTheme.typography.titleSmall)
            Text(
                if (viewModel.exportToCci) "Assemble as .cci (Citra / Azahar)"
                else "Save as decrypted .cia",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        FilterChip(
            selected     = viewModel.exportToCci,
            onClick      = { viewModel.toggleExportFormat(true) },
            label        = { Text("CCI") },
            enabled      = !viewModel.isProcessing && ready,
            leadingIcon  = if (viewModel.exportToCci) {
                { Icon(Icons.Default.Check, null, Modifier.size(18.dp)) }
            } else null
        )
        Spacer(Modifier.width(8.dp))
        FilterChip(
            selected     = !viewModel.exportToCci,
            onClick      = { viewModel.toggleExportFormat(false) },
            label        = { Text("CIA") },
            enabled      = !viewModel.isProcessing && ready,
            leadingIcon  = if (!viewModel.exportToCci) {
                { Icon(Icons.Default.Check, null, Modifier.size(18.dp)) }
            } else null
        )
    }

    Spacer(Modifier.height(12.dp))

    // Step 3: Destination / start
    StepCard(
        title       = "4. Start Decryption",
        description = when {
            viewModel.isProcessing && isBatch ->
                "Batch processing (${viewModel.currentBatchIndex + 1}/${viewModel.batchQueue.size})..."
            viewModel.isProcessing  -> "Processing..."
            viewModel.progress >= 1f -> "Decryption complete!"
            isBatch                  -> "Select output folder for batch"
            else                     -> "Choose where to save the result"
        },
        icon        = Icons.Default.CheckCircle,
        isCompleted = viewModel.progress >= 1f,
        enabled     = !viewModel.isProcessing && ready && (viewModel.ciaFileUri != null || isBatch),
        onClick     = {
            if (isBatch) pickBatchDest.launch(null)
            else createDestFile.launch(viewModel.suggestedFileName)
        }
    )
}

@Composable
fun ProgressAndStatus(viewModel: DecryptViewModel) {
    viewModel.currentSmdh?.let { smdh ->
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 24.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
            )
        ) {
            Row(
                modifier          = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                smdh.icon?.let { icon ->
                    Image(
                        bitmap            = icon.asImageBitmap(),
                        contentDescription = "Game icon",
                        modifier          = Modifier.size(64.dp).clip(MaterialTheme.shapes.medium)
                    )
                    Spacer(Modifier.width(16.dp))
                }
                Column {
                    Text(smdh.shortDescription, style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold)
                    Text(smdh.publisher, style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }

    if (viewModel.isProcessing || viewModel.progress > 0f) {
        Column(
            modifier              = Modifier.fillMaxWidth(),
            horizontalAlignment   = Alignment.CenterHorizontally
        ) {
            Text(
                "Overall Progress: ${(viewModel.progress * 100).toInt()}%",
                style = MaterialTheme.typography.labelLarge
            )
            Spacer(Modifier.height(8.dp))
            if (viewModel.isProcessing && viewModel.progress <= 0f) {
                LinearProgressIndicator(
                    modifier    = Modifier.fillMaxWidth().height(12.dp),
                    strokeCap   = StrokeCap.Round
                )
            } else {
                LinearProgressIndicator(
                    progress    = { viewModel.progress },
                    modifier    = Modifier.fillMaxWidth().height(12.dp),
                    strokeCap   = StrokeCap.Round
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    Card(
        colors   = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Info, null, Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("Status", style = MaterialTheme.typography.titleSmall)
            }
            Spacer(Modifier.height(8.dp))
            Text(
                viewModel.statusMessage,
                style      = MaterialTheme.typography.bodyMedium,
                lineHeight = 20.sp
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StepCard(
    title:       String,
    description: String,
    icon:        ImageVector,
    isCompleted: Boolean,
    enabled:     Boolean,
    onClick:     () -> Unit
) {
    Card(
        onClick  = onClick,
        enabled  = enabled,
        modifier = Modifier.fillMaxWidth(),
        colors   = CardDefaults.cardColors(
            containerColor = if (isCompleted)
                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f)
            else
                MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            modifier          = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                color   = if (isCompleted) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.secondary,
                shape   = MaterialTheme.shapes.medium,
                modifier = Modifier.size(48.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = if (isCompleted) Icons.Default.Check else icon,
                        contentDescription = null,
                        tint        = MaterialTheme.colorScheme.onPrimary
                    )
                }
            }
            Spacer(Modifier.width(16.dp))
            Column {
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(
                    description,
                    style   = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                    color   = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}